// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Chrome/Chromium to render SPAs and extract real form elements

#![allow(dead_code)]

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
    /// Optional JWT/Bearer token for authenticated scanning
    auth_token: Option<String>,
}

impl HeadlessCrawler {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: None,
        }
    }

    /// Create a new headless crawler with authentication token
    pub fn with_auth(timeout_secs: u64, token: Option<String>) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: token,
        }
    }

    /// Extract forms from a JavaScript-rendered page
    pub async fn extract_forms(&self, url: &str) -> Result<Vec<DiscoveredForm>> {
        info!("[Headless] Launching browser for: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();

        // Run headless_chrome in blocking task (it's synchronous)
        let forms = tokio::task::spawn_blocking(move || {
            Self::extract_forms_sync(&url_owned, timeout, auth_token.as_deref())
        })
        .await
        .context("Headless browser task panicked")??;

        info!("[Headless] Found {} forms on {}", forms.len(), url);
        Ok(forms)
    }

    /// Synchronous form extraction (runs in blocking thread)
    fn extract_forms_sync(url: &str, timeout: Duration, auth_token: Option<&str>) -> Result<Vec<DiscoveredForm>> {
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

        // If we have an auth token, first navigate to the base URL and inject it
        if let Some(token) = auth_token {
            info!("[Headless] Injecting authentication token into browser session");

            // Navigate to the URL first to set up the origin
            tab.navigate_to(url)
                .context("Failed to navigate to URL")?;
            tab.wait_until_navigated()
                .context("Navigation timeout")?;

            // Inject token into localStorage (common pattern for SPAs)
            let js_inject_token = format!(r#"
                localStorage.setItem('token', '{}');
                localStorage.setItem('accessToken', '{}');
                localStorage.setItem('auth_token', '{}');
                localStorage.setItem('jwt', '{}');
            "#, token, token, token, token);
            let _ = tab.evaluate(&js_inject_token, false);

            // Reload the page to apply authentication
            tab.reload(true, None)
                .context("Failed to reload with auth")?;
            tab.wait_until_navigated()
                .context("Navigation timeout after auth")?;
        } else {
            tab.navigate_to(url)
                .context("Failed to navigate to URL")?;
            tab.wait_until_navigated()
                .context("Navigation timeout")?;
        }

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
        // Comprehensive form extraction - handles Vue/Vuetify, React, Angular, and traditional forms
        let js_extract = r#"
            (function() {
                const results = [];
                const processedContainers = new Set();

                function extractInput(el, index) {
                    const tagName = el.tagName.toLowerCase();
                    // Get name from multiple sources, generate fallback if none exist
                    let name = el.name || el.id || el.getAttribute('aria-label') || el.placeholder;

                    // For Vuetify, check parent label
                    if (!name) {
                        const label = el.closest('.v-input')?.querySelector('.v-label')?.textContent?.trim();
                        if (label) name = label.toLowerCase().replace(/[^a-z0-9]/g, '_');
                    }

                    if (!name) {
                        // Generate fallback name from type/tag and index
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
                        required: el.required || el.getAttribute('aria-required') === 'true' || el.closest('.v-input--required') !== null
                    };

                    // For SELECT elements
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

                    // For Vuetify select/autocomplete - check for hidden input with options
                    const vuetifySelect = el.closest('.v-select, .v-autocomplete, .v-combobox');
                    if (vuetifySelect) {
                        info.type = 'select';
                        const menuItems = document.querySelectorAll('.v-list-item');
                        if (menuItems.length > 0) {
                            info.options = Array.from(menuItems).map(item => item.textContent?.trim()).filter(Boolean);
                        }
                    }

                    if (inputType === 'checkbox' || inputType === 'radio') {
                        info.value = el.checked ? (el.value || 'on') : null;
                    }

                    return info;
                }

                // 1. Traditional <form> elements
                document.querySelectorAll('form').forEach(form => {
                    processedContainers.add(form);
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

                // 2. Vuetify v-form components (rendered as div with specific classes)
                document.querySelectorAll('.v-form, [class*="v-form"]').forEach(vform => {
                    if (processedContainers.has(vform)) return;
                    processedContainers.add(vform);
                    const inputs = [];
                    let idx = 0;
                    vform.querySelectorAll('input, textarea, select, .v-input input, .v-input textarea').forEach(el => {
                        if (el.closest('.v-form') === vform || el.closest('[class*="v-form"]') === vform) {
                            const info = extractInput(el, idx++);
                            if (info) inputs.push(info);
                        }
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // 3. Form-like containers by class patterns
                const formPatterns = [
                    '[class*="form"]', '[class*="Form"]',
                    '[class*="contact"]', '[class*="signup"]', '[class*="signin"]', '[class*="login"]', '[class*="register"]',
                    '[class*="checkout"]', '[class*="payment"]', '[class*="shipping"]', '[class*="calculator"]',
                    '[role="form"]', '[data-form]'
                ];
                document.querySelectorAll(formPatterns.join(', ')).forEach(container => {
                    if (processedContainers.has(container)) return;
                    if (container.closest('form') || container.closest('.v-form')) return;
                    processedContainers.add(container);

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

                // 4. Vuetify cards/dialogs that contain inputs (common pattern)
                document.querySelectorAll('.v-card, .v-dialog, .v-sheet').forEach(container => {
                    if (processedContainers.has(container)) return;
                    const inputs = [];
                    let idx = 0;
                    container.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach(el => {
                        if (!el.closest('form') && !el.closest('.v-form')) {
                            const info = extractInput(el, idx++);
                            if (info) inputs.push(info);
                        }
                    });
                    if (inputs.length >= 2) { // At least 2 inputs to be considered a form
                        processedContainers.add(container);
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // 5. Any remaining standalone inputs not in a form
                const standalone = [];
                let standaloneIdx = 0;
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select').forEach(el => {
                    // Skip if already processed
                    for (const container of processedContainers) {
                        if (container.contains(el)) return;
                    }
                    const info = extractInput(el, standaloneIdx++);
                    if (info) standalone.push(info);
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

        let result = tab.evaluate(js_extract, true).context("Failed to extract forms")?;
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
                            debug!("[Headless] Form at {} with {} inputs", action, inputs.len());
                            forms.push(DiscoveredForm {
                                action,
                                method,
                                inputs,
                                discovered_at: original_url.to_string(),
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
        let auth_token = self.auth_token.clone();

        let endpoints = tokio::task::spawn_blocking(move || {
            Self::discover_endpoints_sync(&url_owned, timeout, auth_token.as_deref())
        })
        .await
        .context("Form endpoint discovery task panicked")??;

        info!("[Headless] Discovered {} potential form endpoints", endpoints.len());
        Ok(endpoints)
    }

    /// Synchronous endpoint discovery with network interception
    fn discover_endpoints_sync(url: &str, timeout: Duration, auth_token: Option<&str>) -> Result<Vec<DiscoveredEndpoint>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // If we have auth token, inject it before setting up interception
        if let Some(token) = auth_token {
            info!("[Headless] Setting up authenticated session for endpoint discovery");

            // Navigate first to set origin
            tab.navigate_to(url).context("Failed to navigate for auth setup")?;
            tab.wait_until_navigated().context("Auth setup navigation timeout")?;

            // Inject token into localStorage
            let js_inject_token = format!(r#"
                localStorage.setItem('token', '{}');
                localStorage.setItem('accessToken', '{}');
                localStorage.setItem('auth_token', '{}');
                localStorage.setItem('jwt', '{}');
            "#, token, token, token, token);
            let _ = tab.evaluate(&js_inject_token, false);
        }

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
            move |_transport, _session_id, intercepted: RequestPausedEvent| {
                let request = &intercepted.params.request;
                let method = if request.method.is_empty() { "GET" } else { &request.method };

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
                            content_type: request.headers.0.as_ref()
                                .and_then(|h| h.get("Content-Type").or_else(|| h.get("content-type")))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
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

/// Complete site crawl results
#[derive(Debug, Clone, Default)]
pub struct SiteCrawlResults {
    /// All pages visited during crawl
    pub pages_visited: Vec<String>,
    /// All forms discovered across the site
    pub forms: Vec<DiscoveredForm>,
    /// All API endpoints discovered via network interception
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    /// Internal links found but not yet visited (for reference)
    pub links_found: Vec<String>,
}

impl HeadlessCrawler {
    /// Crawl entire authenticated site - discover all pages, forms, and API endpoints
    /// This is the main entry point for comprehensive site scanning
    pub async fn crawl_authenticated_site(&self, start_url: &str, max_pages: usize) -> Result<SiteCrawlResults> {
        info!("[Headless] Starting full authenticated site crawl: {}", start_url);

        let url_owned = start_url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();

        let results = tokio::task::spawn_blocking(move || {
            Self::crawl_site_sync(&url_owned, timeout, auth_token.as_deref(), max_pages)
        })
        .await
        .context("Site crawl task panicked")??;

        info!(
            "[Headless] Site crawl complete: {} pages, {} forms, {} API endpoints",
            results.pages_visited.len(),
            results.forms.len(),
            results.api_endpoints.len()
        );
        Ok(results)
    }

    /// Synchronous full site crawl
    fn crawl_site_sync(
        start_url: &str,
        timeout: Duration,
        auth_token: Option<&str>,
        max_pages: usize,
    ) -> Result<SiteCrawlResults> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Parse base URL for same-origin checks
        let base_url = url::Url::parse(start_url).context("Invalid start URL")?;
        let base_host = base_url.host_str().unwrap_or("").to_string();

        // Track visited pages and pages to visit
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut to_visit: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        to_visit.push_back(start_url.to_string());

        let mut results = SiteCrawlResults::default();

        // Set up network interception for API discovery
        let captured_requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured_requests);

        let patterns = vec![RequestPattern {
            url_pattern: Some("*".to_string()),
            resource_Type: None,
            request_stage: Some(RequestStage::Request),
        }];

        tab.enable_fetch(Some(&patterns), None)
            .context("Failed to enable fetch interception")?;

        tab.enable_request_interception(Arc::new(
            move |_transport, _session_id, intercepted: RequestPausedEvent| {
                let request = &intercepted.params.request;
                let method = if request.method.is_empty() {
                    "GET"
                } else {
                    &request.method
                };

                // Capture POST/PUT/PATCH/DELETE requests and XHR/fetch GETs to API endpoints
                let url_lower = request.url.to_lowercase();
                let is_api_request = url_lower.contains("/api/")
                    || url_lower.contains("/graphql")
                    || url_lower.contains("/v1/")
                    || url_lower.contains("/v2/")
                    || method != "GET";

                if is_api_request {
                    // Filter out tracking/analytics
                    let should_capture = !url_lower.contains("analytics")
                        && !url_lower.contains("tracking")
                        && !url_lower.contains("pixel")
                        && !url_lower.contains("gtag")
                        && !url_lower.contains("facebook.com")
                        && !url_lower.contains("google-analytics")
                        && !url_lower.contains("sentry.io")
                        && !url_lower.contains("cdn.");

                    if should_capture {
                        if let Ok(mut captured) = captured_clone.lock() {
                            // Avoid duplicates
                            let exists = captured.iter().any(|r| r.url == request.url && r.method == method);
                            if !exists {
                                debug!("[Headless] Captured API: {} {}", method, request.url);
                                captured.push(CapturedRequest {
                                    url: request.url.clone(),
                                    method: method.to_string(),
                                    post_data: request.post_data.clone(),
                                    content_type: request
                                        .headers
                                        .0
                                        .as_ref()
                                        .and_then(|h| {
                                            h.get("Content-Type").or_else(|| h.get("content-type"))
                                        })
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                });
                            }
                        }
                    }
                }

                RequestPausedDecision::Continue(None)
            },
        ))?;

        // Navigate to start URL and inject auth token
        tab.navigate_to(start_url)
            .context("Failed to navigate to start URL")?;
        tab.wait_until_navigated()
            .context("Navigation timeout")?;

        if let Some(token) = auth_token {
            info!("[Headless] Injecting authentication token");
            let js_inject_token = format!(
                r#"
                localStorage.setItem('token', '{}');
                localStorage.setItem('accessToken', '{}');
                localStorage.setItem('auth_token', '{}');
                localStorage.setItem('jwt', '{}');
                sessionStorage.setItem('token', '{}');
                sessionStorage.setItem('accessToken', '{}');
            "#,
                token, token, token, token, token, token
            );
            let _ = tab.evaluate(&js_inject_token, false);

            // Reload to apply auth
            tab.reload(true, None).context("Failed to reload with auth")?;
            tab.wait_until_navigated()
                .context("Navigation timeout after auth")?;
        }

        // Crawl loop
        while let Some(current_url) = to_visit.pop_front() {
            if visited.contains(&current_url) {
                continue;
            }

            if visited.len() >= max_pages {
                info!(
                    "[Headless] Reached max pages limit ({}), stopping crawl",
                    max_pages
                );
                break;
            }

            // Navigate to the page
            if current_url != start_url || visited.is_empty() {
                debug!("[Headless] Navigating to: {}", current_url);
                if tab.navigate_to(&current_url).is_err() {
                    warn!("[Headless] Failed to navigate to: {}", current_url);
                    continue;
                }
                if tab.wait_until_navigated().is_err() {
                    warn!("[Headless] Navigation timeout for: {}", current_url);
                    continue;
                }
            }

            visited.insert(current_url.clone());
            results.pages_visited.push(current_url.clone());

            // Wait for JS to render
            std::thread::sleep(Duration::from_millis(1500));

            // Extract forms from current page
            match Self::extract_forms_from_tab(&tab, &current_url) {
                Ok(page_forms) => {
                    info!(
                        "[Headless] Page {} - found {} forms",
                        current_url,
                        page_forms.len()
                    );
                    results.forms.extend(page_forms);
                }
                Err(e) => {
                    warn!("[Headless] Failed to extract forms from {}: {}", current_url, e);
                }
            }

            // Extract internal links
            let js_extract_links = format!(
                r#"
                (function() {{
                    const links = new Set();
                    const baseHost = '{}';

                    // Get all anchor links
                    document.querySelectorAll('a[href]').forEach(a => {{
                        try {{
                            const href = a.href;
                            if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) return;

                            const url = new URL(href, window.location.origin);
                            // Same origin check
                            if (url.hostname === baseHost || url.hostname.endsWith('.' + baseHost)) {{
                                // Skip file downloads and external resources
                                const path = url.pathname.toLowerCase();
                                if (path.endsWith('.pdf') || path.endsWith('.zip') || path.endsWith('.doc')) return;
                                if (path.endsWith('.png') || path.endsWith('.jpg') || path.endsWith('.gif')) return;

                                // Clean URL (remove hash)
                                url.hash = '';
                                links.add(url.href);
                            }}
                        }} catch(e) {{}}
                    }});

                    // Also check for SPA navigation links (router-link, etc)
                    document.querySelectorAll('[to], [routerlink], [ng-href]').forEach(el => {{
                        const to = el.getAttribute('to') || el.getAttribute('routerlink') || el.getAttribute('ng-href');
                        if (to && !to.startsWith('#')) {{
                            try {{
                                const url = new URL(to, window.location.origin);
                                if (url.hostname === baseHost) {{
                                    links.add(url.href);
                                }}
                            }} catch(e) {{}}
                        }}
                    }});

                    return JSON.stringify(Array.from(links));
                }})()
            "#,
                base_host
            );

            if let Ok(result) = tab.evaluate(&js_extract_links, true) {
                if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(links) = serde_json::from_str::<Vec<String>>(&json_str) {
                        for link in links {
                            if !visited.contains(&link) && !to_visit.contains(&link) {
                                to_visit.push_back(link.clone());
                                results.links_found.push(link);
                            }
                        }
                    }
                }
            }

            // Try clicking on navigation items to discover more content
            let _ = tab.evaluate(
                r#"
                (function() {
                    // Click on nav items that might reveal more content
                    document.querySelectorAll('nav a, [role="navigation"] a, .nav-link, .menu-item').forEach((el, i) => {
                        if (i < 5) { // Limit to avoid too many clicks
                            el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
                        }
                    });
                })()
            "#,
                false,
            );
        }

        // Disable interception
        let _ = tab.disable_fetch();

        // Collect API endpoints
        if let Ok(captured) = captured_requests.lock() {
            for req in captured.iter() {
                results.api_endpoints.push(DiscoveredEndpoint {
                    url: req.url.clone(),
                    method: req.method.clone(),
                    content_type: req.content_type.clone(),
                });
            }
        }

        // Store remaining links for reference
        results.links_found = to_visit.into_iter().collect();

        Ok(results)
    }
}
