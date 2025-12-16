// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Chrome/Chromium to render SPAs and extract real form elements

use crate::crawler::{DiscoveredForm, FormInput};
use anyhow::{Context, Result};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use futures::StreamExt;
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

        // Launch browser
        let (mut browser, mut handler) = Browser::launch(
            BrowserConfig::builder()
                .with_head(false)
                .window_size(1920, 1080)
                .request_timeout(self.timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser config error: {}", e))?
        )
        .await
        .context("Failed to launch headless browser")?;

        // Spawn handler task
        let handle = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
        });

        // Navigate to page
        let page = browser
            .new_page(url)
            .await
            .context("Failed to create new page")?;

        // Wait for page to load and JS to execute
        page.wait_for_navigation()
            .await
            .context("Navigation timeout")?;

        // Additional wait for dynamic content
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Extract all forms from rendered DOM
        let forms = self.extract_forms_from_page(&page, url).await?;

        info!("[Headless] Found {} forms on {}", forms.len(), url);

        // Cleanup
        browser.close().await.ok();
        handle.abort();

        Ok(forms)
    }

    /// Extract form elements from the rendered page
    async fn extract_forms_from_page(
        &self,
        page: &chromiumoxide::Page,
        base_url: &str,
    ) -> Result<Vec<DiscoveredForm>> {
        let mut forms = Vec::new();

        // JavaScript to extract all forms and inputs from the rendered DOM
        let js_extract = r#"
            (function() {
                const results = [];

                // Get all form elements
                const formElements = document.querySelectorAll('form');
                formElements.forEach(form => {
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
                            method: form.method || 'POST',
                            inputs: inputs
                        });
                    }
                });

                // Also find form-like containers (div with inputs but no form tag)
                const containers = document.querySelectorAll('[class*="form"], [class*="contact"], [class*="signup"], [class*="login"], [role="form"]');
                containers.forEach(container => {
                    // Skip if already inside a form
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

                // Find standalone inputs not in any form or container
                const allInputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select');
                const standaloneInputs = [];
                allInputs.forEach(input => {
                    if (!input.closest('form') && !input.closest('[class*="form"]')) {
                        const name = input.name || input.id || input.getAttribute('aria-label') || input.placeholder;
                        if (name) {
                            standaloneInputs.push({
                                name: name,
                                type: input.type || 'text',
                                value: input.value || null
                            });
                        }
                    }
                });
                if (standaloneInputs.length > 0) {
                    results.push({
                        action: window.location.href,
                        method: 'POST',
                        inputs: standaloneInputs
                    });
                }

                return results;
            })()
        "#;

        let result = page
            .evaluate(js_extract)
            .await
            .context("Failed to execute form extraction JS")?;

        // Parse the result
        if let Some(form_data) = result.value() {
            if let Some(arr) = form_data.as_array() {
                for form_obj in arr {
                    let action = form_obj
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or(base_url)
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
                            discovered_at: base_url.to_string(),
                        });
                    }
                }
            }
        }

        Ok(forms)
    }

    /// Check if headless browser is available
    pub async fn is_available() -> bool {
        // Try to launch browser briefly
        match Browser::launch(
            BrowserConfig::builder()
                .with_head(false)
                .build()
                .unwrap_or_default()
        ).await {
            Ok((mut browser, _)) => {
                browser.close().await.ok();
                true
            }
            Err(e) => {
                debug!("[Headless] Browser not available: {}", e);
                false
            }
        }
    }
}
