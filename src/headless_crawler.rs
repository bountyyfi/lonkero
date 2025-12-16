// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Chrome/Chromium to render SPAs and extract real form elements

use crate::crawler::{DiscoveredForm, FormInput};
use anyhow::{Context, Result};
use headless_chrome::{Browser, LaunchOptions};
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

        // Extract forms using JavaScript
        let js_extract = r#"
            (function() {
                const results = [];

                // Get all form elements
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        const name = input.name || input.id || input.getAttribute('aria-label') || input.placeholder;
                        if (name && input.type !== 'hidden' && input.type !== 'submit') {
                            inputs.push({
                                name: name,
                                type: input.type || 'text',
                                value: input.value || null
                            });
                        }
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'POST').toUpperCase(),
                            inputs: inputs
                        });
                    }
                });

                // Find form-like containers (div with inputs but no form tag)
                document.querySelectorAll('[class*="form"], [class*="contact"], [class*="signup"], [class*="login"], [role="form"]').forEach(container => {
                    if (container.closest('form')) return;
                    const inputs = [];
                    container.querySelectorAll('input, textarea, select').forEach(input => {
                        const name = input.name || input.id || input.getAttribute('aria-label') || input.placeholder;
                        if (name && input.type !== 'hidden' && input.type !== 'submit') {
                            inputs.push({
                                name: name,
                                type: input.type || 'text',
                                value: input.value || null
                            });
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

                // Find standalone inputs
                const standalone = [];
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select').forEach(input => {
                    if (!input.closest('form') && !input.closest('[class*="form"]')) {
                        const name = input.name || input.id || input.getAttribute('aria-label') || input.placeholder;
                        if (name) {
                            standalone.push({
                                name: name,
                                type: input.type || 'text',
                                value: input.value || null
                            });
                        }
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

                                    inputs.push(FormInput {
                                        name,
                                        input_type,
                                        value,
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
}
