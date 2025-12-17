// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Chrome/Chromium to render SPAs and extract real form elements

use crate::crawler::{DiscoveredForm, FormInput};
use anyhow::{Context, Result};
use headless_chrome::browser::tab::RequestPausedDecision;
use headless_chrome::protocol::cdp::Fetch::{events::RequestPausedEvent, RequestPattern, RequestStage};
use headless_chrome::{Browser, LaunchOptions};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Headless browser crawler for SPA form detection
pub struct HeadlessCrawler {
    timeout: Duration,
}

impl HeadlessCrawler {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Extract forms from a JavaScript-rendered page
    pub async fn extract_forms(&self, url: &str) -> Result<Vec<DiscoveredForm>> {
        info!("[Headless] Launching browser for: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;

        // Run headless_chrome in blocking task (it's synchronous)
        let forms = tokio::task::spawn_blocking(move || {
            Self::extract_forms_sync(&url_owned, timeout)
        })
        .await
        .context("Headless browser task panicked")??;

        info!("[Headless] Found {} forms on {}", forms.len(), url);
        Ok(forms)
    }

    /// Synchronous form extraction (runs in blocking thread)
    fn extract_forms_sync(url: &str, timeout: Duration) -> Result<Vec<DiscoveredForm>> {
        // Launch browser
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch options error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        // Create new tab and navigate
        let tab = browser.new_tab().context("Failed to create new tab")?;

        tab.navigate_to(url)
            .context("Failed to navigate to URL")?;

        // Wait for page to load
        tab.wait_until_navigated()
            .context("Navigation timeout")?;

        // Additional wait for JS to render
        std::thread::sleep(Duration::from_secs(2));

        // Extract forms using JavaScript - handles all input types including SELECT
        let js_extract = r#"
            (function() {
                const results = [];

                // Helper to extract input info including SELECT options
                function extractInput(el, index) {
                    const tagName = el.tagName.toLowerCase();
                    // Get name from multiple sources, generate fallback if none exist
                    let name = el.name || el.id || el.getAttribute('aria-label') || el.placeholder;
                    if (!name) {
                        // Generate fallback name from type/tag and index for controlled inputs
                        const inputType = el.type || tagName;
                        name = inputType + '_field_' + index;
                    }

                    const inputType = el.type || tagName;
                    if (inputType === 'hidden' || inputType === 'submit' || inputType === 'button') return null;

                    const info = {
                        name: name,
                        type: inputType,
                        value: el.value || null,
                        options: null,
                        required: el.required || el.getAttribute('aria-required') === 'true'
                    };

                    // For SELECT elements, get all options
                    if (tagName === 'select') {
                        info.type = 'select';
                        info.options = [];
                        el.querySelectorAll('option').forEach(opt => {
                            if (opt.value && opt.value !== '') {
                                info.options.push(opt.value);
                            }
                        });
                        // Set value to first valid option if not already set
                        if (!info.value && info.options.length > 0) {
                            info.value = info.options[0];
                        }
                    }

                    // For checkboxes/radio, capture checked state
                    if (inputType === 'checkbox' || inputType === 'radio') {
                        info.value = el.checked ? (el.value || 'on') : null;
                    }

                    return info;
                }

                // Get all form elements
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    let idx = 0;
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'POST').toUpperCase(),
                            inputs: inputs
                        });
                    }
                });

                // Find form-like containers
                document.querySelectorAll('[class*="form"], [class*="contact"], [class*="signup"], [class*="login"], [role="form"]').forEach(container => {
                    if (container.closest('form')) return;
                    const inputs = [];
                    let idx = 0;
                    container.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // Find standalone inputs
                const standalone = [];
                let standaloneIdx = 0;
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select').forEach(el => {
                    if (!el.closest('form') && !el.closest('[class*="form"]')) {
                        const info = extractInput(el, standaloneIdx++);
                        if (info) standalone.push(info);
                    }
                });
                if (standalone.length > 0) {
                    results.push({
                        action: window.location.href,
                        method: 'POST',
                        inputs: standalone
                    });
                }

                return JSON.stringify(results);
            })()
        "#;

        let result = tab.evaluate(js_extract, true)
            .context("Failed to execute JavaScript")?;

        let mut forms = Vec::new();

        if let Some(json_str) = result.value {
            if let Some(s) = json_str.as_str() {
                if let Ok(form_data) = serde_json::from_str::<Vec<serde_json::Value>>(s) {
                    for form_obj in form_data {
                        let action = form_obj
                            .get("action")
                            .and_then(|v| v.as_str())
                            .unwrap_or(url)
                            .to_string();

                        let method = form_obj
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("POST")
                            .to_uppercase();

                        let mut inputs = Vec::new();
                        if let Some(inputs_arr) = form_obj.get("inputs").and_then(|v| v.as_array()) {
                            for input_obj in inputs_arr {
                                let name = input_obj
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                if !name.is_empty() {
                                    let input_type = input_obj
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("text")
                                        .to_string();

                                    let value = input_obj
                                        .get("value")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    // Extract SELECT options if present
                                    let options = input_obj
                                        .get("options")
                                        .and_then(|v| v.as_array())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                .collect()
                                        });

                                    let required = input_obj
                                        .get("required")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    inputs.push(FormInput {
                                        name,
                                        input_type,
                                        value,
                                        options,
                                        required,
                                    });
                                }
                            }
                        }

                        if !inputs.is_empty() {
                            debug!("[Headless] Form at {} with {} inputs", action, inputs.len());
                            forms.push(DiscoveredForm {
                                action,
                                method,
                                inputs,
                                discovered_at: url.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(forms)
    }

    /// Check if headless browser is available
    pub async fn is_available() -> bool {
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

    /// Detect multi-stage forms by filling and submitting forms
    /// Returns (initial_forms, follow_up_forms) - follow_up_forms appear after submission
    pub async fn detect_multi_stage_forms(&self, url: &str, form_values: &[(String, String)]) -> Result<Vec<DiscoveredForm>> {
        info!("[Headless] Detecting multi-stage forms at: {}", url);

        let url_owned = url.to_string();
        let values_owned: Vec<(String, String)> = form_values.to_vec();
        let timeout = self.timeout;

        let forms = tokio::task::spawn_blocking(move || {
            Self::detect_multi_stage_sync(&url_owned, &values_owned, timeout)
        })
        .await
        .context("Multi-stage detection task panicked")??;

        info!("[Headless] Multi-stage detection found {} follow-up forms", forms.len());
        Ok(forms)
    }

    /// Synchronous multi-stage form detection
    fn detect_multi_stage_sync(url: &str, form_values: &[(String, String)], timeout: Duration) -> Result<Vec<DiscoveredForm>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;
        std::thread::sleep(Duration::from_secs(2));

        // Fill form fields
        for (name, value) in form_values {
            let js_fill = format!(
                r#"
                (function() {{
                    const el = document.querySelector('[name="{}"]') || document.getElementById('{}');
                    if (el) {{
                        el.value = '{}';
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }}
                    return false;
                }})()
                "#,
                name.replace("'", "\\'"),
                name.replace("'", "\\'"),
                value.replace("'", "\\'")
            );
            let _ = tab.evaluate(&js_fill, true);
        }

        // Submit form
        let js_submit = r#"
            (function() {
                const form = document.querySelector('form');
                if (form) {
                    const submit = form.querySelector('[type="submit"], button:not([type="button"])');
                    if (submit) {
                        submit.click();
                        return 'clicked';
                    }
                    form.submit();
                    return 'submitted';
                }
                return 'no_form';
            })()
        "#;

        let result = tab.evaluate(js_submit, true).context("Failed to submit form")?;
        debug!("[Headless] Form submit result: {:?}", result.value);

        // Wait for page to update after submission
        std::thread::sleep(Duration::from_secs(3));

        // Check for new forms on the page (could be same page with new form or redirected)
        let forms = Self::extract_forms_from_tab(&tab, url)?;

        Ok(forms)
    }

    /// Extract forms from an existing tab
    fn extract_forms_from_tab(tab: &headless_chrome::Tab, original_url: &str) -> Result<Vec<DiscoveredForm>> {
        let js_extract = r#"
            (function() {
                const results = [];

                function extractInput(el) {
                    const tagName = el.tagName.toLowerCase();
                    const name = el.name || el.id || el.getAttribute('aria-label') || el.placeholder;
                    if (!name) return null;

                    const inputType = el.type || tagName;
                    if (inputType === 'hidden' || inputType === 'submit' || inputType === 'button') return null;

                    const info = {
                        name: name,
                        type: inputType,
                        value: el.value || null,
                        options: null,
                        required: el.required || el.getAttribute('aria-required') === 'true'
                    };

                    if (tagName === 'select') {
                        info.type = 'select';
                        info.options = [];
                        el.querySelectorAll('option').forEach(opt => {
                            if (opt.value && opt.value !== '') {
                                info.options.push(opt.value);
                            }
                        });
                        if (!info.value && info.options.length > 0) {
                            info.value = info.options[0];
                        }
                    }

                    if (inputType === 'checkbox' || inputType === 'radio') {
                        info.value = el.checked ? (el.value || 'on') : null;
                    }

                    return info;
                }

                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'POST').toUpperCase(),
                            inputs: inputs,
                            is_followup: true
                        });
                    }
                });

                return JSON.stringify(results);
            })()
        "#;

        let result = tab.evaluate(js_extract, true).context("Failed to extract follow-up forms")?;
        let mut forms = Vec::new();

        if let Some(json_str) = result.value {
            if let Some(s) = json_str.as_str() {
                if let Ok(form_data) = serde_json::from_str::<Vec<serde_json::Value>>(s) {
                    for form_obj in form_data {
                        let action = form_obj.get("action")
                            .and_then(|v| v.as_str())
                            .unwrap_or(original_url)
                            .to_string();

                        let method = form_obj.get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("POST")
                            .to_uppercase();

                        let mut inputs = Vec::new();
                        if let Some(inputs_arr) = form_obj.get("inputs").and_then(|v| v.as_array()) {
                            for input_obj in inputs_arr {
                                let name = input_obj.get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                if !name.is_empty() {
                                    let input_type = input_obj.get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("text")
                                        .to_string();

                                    let value = input_obj.get("value")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    let options = input_obj.get("options")
                                        .and_then(|v| v.as_array())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                .collect()
                                        });

                                    let required = input_obj.get("required")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    inputs.push(FormInput {
                                        name,
                                        input_type,
                                        value,
                                        options,
                                        required,
                                    });
                                }
                            }
                        }

                        if !inputs.is_empty() {
                            debug!("[Headless] Follow-up form at {} with {} inputs", action, inputs.len());
                            forms.push(DiscoveredForm {
                                action,
                                method,
                                inputs,
                                discovered_at: format!("{} (follow-up)", original_url),
                            });
                        }
                    }
                }
            }
        }

        Ok(forms)
    }

    /// Discover the actual API endpoint for SPA forms by intercepting network requests
    /// This is crucial for React/Next.js apps where forms don't have HTML action attributes
    /// but instead use fetch/axios to POST to API routes
    pub async fn discover_form_endpoints(&self, url: &str) -> Result<Vec<DiscoveredEndpoint>> {
        info!("[Headless] Discovering form endpoints via network interception: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;

        let endpoints = tokio::task::spawn_blocking(move || {
            Self::discover_endpoints_sync(&url_owned, timeout)
        })
        .await
        .context("Form endpoint discovery task panicked")??;

        info!("[Headless] Discovered {} potential form endpoints", endpoints.len());
        Ok(endpoints)
    }

    /// Synchronous endpoint discovery with network interception
    fn discover_endpoints_sync(url: &str, timeout: Duration) -> Result<Vec<DiscoveredEndpoint>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Store captured requests
        let captured_requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured_requests);

        // Enable network interception - intercept all POST/PUT requests
        let patterns = vec![
            RequestPattern {
                url_pattern: Some("*".to_string()),
                resource_Type: None,
                request_stage: Some(RequestStage::Request),
            },
        ];

        tab.enable_fetch(Some(&patterns), None)
            .context("Failed to enable fetch interception")?;

        // Set up the request interceptor
        tab.enable_request_interception(Arc::new(
            move |transport, session_id, intercepted: RequestPausedEvent| {
                let request = &intercepted.params.request;
                let method = request.method.as_deref().unwrap_or("GET");

                // Only capture POST/PUT/PATCH requests (form submissions)
                if method == "POST" || method == "PUT" || method == "PATCH" {
                    let url = request.url.clone();
                    let post_data = request.post_data.clone();

                    debug!("[Headless] Intercepted {} request to: {}", method, url);

                    if let Ok(mut captured) = captured_clone.lock() {
                        captured.push(CapturedRequest {
                            url,
                            method: method.to_string(),
                            post_data,
                            content_type: request.headers.as_ref()
                                .and_then(|h| h.get("Content-Type").or(h.get("content-type")))
                                .map(|v| v.to_string()),
                        });
                    }
                }

                // Continue the request (don't block it)
                RequestPausedDecision::Continue(None)
            },
        ))?;

        // Navigate to the page
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;
        std::thread::sleep(Duration::from_secs(2));

        // Find and try to submit forms with test data
        let js_fill_and_submit = r#"
            (function() {
                const results = [];

                // Find all forms and form-like containers
                const forms = document.querySelectorAll('form, [class*="form"], [class*="contact"], [role="form"]');

                forms.forEach((form, formIndex) => {
                    // Fill inputs with test data
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const type = el.type || el.tagName.toLowerCase();
                        if (type === 'hidden' || type === 'submit' || type === 'button') return;

                        // Fill with test values based on input type/name
                        let testValue = 'test';
                        const name = (el.name || el.id || '').toLowerCase();

                        if (type === 'email' || name.includes('email')) {
                            testValue = 'test@example.com';
                        } else if (type === 'tel' || name.includes('phone')) {
                            testValue = '+1234567890';
                        } else if (name.includes('name')) {
                            testValue = 'Test User';
                        } else if (name.includes('message') || name.includes('comment') || type === 'textarea') {
                            testValue = 'Test message';
                        } else if (type === 'select') {
                            // Select first non-empty option
                            const opt = el.querySelector('option[value]:not([value=""])');
                            if (opt) testValue = opt.value;
                        } else if (type === 'checkbox' || type === 'radio') {
                            el.checked = true;
                            return;
                        }

                        el.value = testValue;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    });

                    results.push({ formIndex, filled: true });
                });

                return JSON.stringify(results);
            })()
        "#;

        let _ = tab.evaluate(js_fill_and_submit, true);

        // Try to submit the first form
        let js_submit = r#"
            (function() {
                // Try clicking submit buttons
                const submitBtn = document.querySelector(
                    'form button[type="submit"], form input[type="submit"], ' +
                    'form button:not([type="button"]), ' +
                    '[class*="form"] button[type="submit"], ' +
                    '[class*="form"] button:not([type="button"]), ' +
                    'button[class*="submit"], button[class*="send"]'
                );

                if (submitBtn) {
                    submitBtn.click();
                    return 'clicked_submit';
                }

                // Try form.submit()
                const form = document.querySelector('form');
                if (form) {
                    // Create and dispatch submit event (allows JS handlers to run)
                    const event = new Event('submit', { bubbles: true, cancelable: true });
                    form.dispatchEvent(event);
                    return 'dispatched_submit';
                }

                return 'no_form_found';
            })()
        "#;

        let submit_result = tab.evaluate(js_submit, true);
        debug!("[Headless] Submit result: {:?}", submit_result.ok().and_then(|r| r.value));

        // Wait for any async requests to complete
        std::thread::sleep(Duration::from_secs(3));

        // Disable interception
        let _ = tab.disable_fetch();

        // Get captured requests
        let endpoints = captured_requests.lock()
            .map(|captured| {
                captured.iter()
                    .filter(|req| {
                        // Filter to only include likely form submission endpoints
                        let url_lower = req.url.to_lowercase();
                        // Exclude tracking/analytics
                        !url_lower.contains("analytics") &&
                        !url_lower.contains("tracking") &&
                        !url_lower.contains("pixel") &&
                        !url_lower.contains("gtag") &&
                        !url_lower.contains("facebook.com") &&
                        !url_lower.contains("google-analytics")
                    })
                    .map(|req| DiscoveredEndpoint {
                        url: req.url.clone(),
                        method: req.method.clone(),
                        content_type: req.content_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(endpoints)
    }
}

/// Captured network request during form submission interception
#[derive(Debug, Clone)]
struct CapturedRequest {
    url: String,
    method: String,
    post_data: Option<String>,
    content_type: Option<String>,
}

/// Discovered form submission endpoint
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub content_type: Option<String>,
}
