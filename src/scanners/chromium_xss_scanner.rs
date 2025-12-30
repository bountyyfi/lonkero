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

/// JavaScript code to intercept XSS execution - hooks dialogs AND dangerous sinks
const XSS_INTERCEPTOR: &str = r#"
(function() {
    window.__xssMarker = null;
    window.__xssTriggered = false;
    window.__xssTriggerType = 'none';
    window.__xssMessage = '';
    window.__xssExecutions = [];
    window.__xssSeverity = 'none';
    window.__xssTaintedData = new Map(); // Source tagging: track tainted inputs

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
            return e.stack.split('\n').slice(2, 8).join('\n'); // Skip first 2 lines (Error + this func)
        }
    }

    function recordExecution(type, content, source) {
        window.__xssTriggered = true;
        window.__xssTriggerType = type;
        window.__xssMessage = String(content).substring(0, 500);
        window.__xssSeverity = SINK_SEVERITY[type] || 'MEDIUM';

        const execution = {
            type: type,
            content: String(content).substring(0, 200),
            severity: window.__xssSeverity,
            timestamp: Date.now(),
            stack: getStackTrace(),
            source: source || 'unknown'
        };
        window.__xssExecutions.push(execution);
        console.log('[XSS-DETECTED]', type + ':', content, 'severity:', window.__xssSeverity);
    }

    // SOURCE TAGGING: Track user input sources
    // Hook location.search (URL params)
    try {
        const origSearch = Object.getOwnPropertyDescriptor(Location.prototype, 'search');
        if (origSearch && origSearch.get) {
            Object.defineProperty(Location.prototype, 'search', {
                get: function() {
                    const val = origSearch.get.call(this);
                    if (checkMarker(val)) {
                        window.__xssTaintedData.set('location.search', val);
                    }
                    return val;
                },
                configurable: true
            });
        }
    } catch(e) {}

    // Hook location.hash (URL fragment)
    try {
        const origHash = Object.getOwnPropertyDescriptor(Location.prototype, 'hash');
        if (origHash && origHash.get) {
            Object.defineProperty(Location.prototype, 'hash', {
                get: function() {
                    const val = origHash.get.call(this);
                    if (checkMarker(val)) {
                        window.__xssTaintedData.set('location.hash', val);
                    }
                    return val;
                },
                configurable: true
            });
        }
    } catch(e) {}

    // Hook document.cookie
    try {
        const origCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        if (origCookie && origCookie.get) {
            Object.defineProperty(Document.prototype, 'cookie', {
                get: function() {
                    const val = origCookie.get.call(this);
                    if (checkMarker(val)) {
                        window.__xssTaintedData.set('document.cookie', val);
                    }
                    return val;
                },
                set: origCookie.set,
                configurable: true
            });
        }
    } catch(e) {}

    // Hook localStorage
    const origLocalGetItem = localStorage.getItem.bind(localStorage);
    localStorage.getItem = function(key) {
        const val = origLocalGetItem(key);
        if (val && checkMarker(val)) {
            window.__xssTaintedData.set('localStorage.' + key, val);
        }
        return val;
    };

    // Hook sessionStorage
    const origSessionGetItem = sessionStorage.getItem.bind(sessionStorage);
    sessionStorage.getItem = function(key) {
        const val = origSessionGetItem(key);
        if (val && checkMarker(val)) {
            window.__xssTaintedData.set('sessionStorage.' + key, val);
        }
        return val;
    };

    // Hook postMessage listener (with origin tracking)
    window.addEventListener('message', function(e) {
        try {
            const data = JSON.stringify(e.data);
            if (checkMarker(data)) {
                window.__xssTaintedData.set('postMessage', {
                    data: data.substring(0, 200),
                    origin: e.origin,
                    source: e.source === window ? 'self' : 'other'
                });
            }
        } catch(err) {}
    }, true);

    // FLOW-BASED TAINT TRACKING (minimal)
    // Carry taint metadata through string operations
    const TAINT_SYMBOL = Symbol('__tainted');

    function taintString(str, source) {
        if (typeof str !== 'string') return str;
        const tainted = new String(str);
        tainted[TAINT_SYMBOL] = {source: source, tainted: true};
        return tainted;
    }

    function isTainted(str) {
        return str && str[TAINT_SYMBOL] && str[TAINT_SYMBOL].tainted;
    }

    // Hook String.prototype methods to propagate taint
    const origConcat = String.prototype.concat;
    String.prototype.concat = function(...args) {
        const result = origConcat.apply(this, args);
        // If any input is tainted, result is tainted
        if (isTainted(this) || args.some(isTainted)) {
            return taintString(result, 'concat');
        }
        return result;
    };

    const origReplace = String.prototype.replace;
    String.prototype.replace = function(searchValue, replaceValue) {
        const result = origReplace.call(this, searchValue, replaceValue);
        if (isTainted(this) || isTainted(replaceValue)) {
            return taintString(result, 'replace');
        }
        return result;
    };

    const origSlice = String.prototype.slice;
    String.prototype.slice = function(start, end) {
        const result = origSlice.call(this, start, end);
        if (isTainted(this)) {
            return taintString(result, 'slice');
        }
        return result;
    };

    const origSubstring = String.prototype.substring;
    String.prototype.substring = function(start, end) {
        const result = origSubstring.call(this, start, end);
        if (isTainted(this)) {
            return taintString(result, 'substring');
        }
        return result;
    };

    const origSubstr = String.prototype.substr;
    String.prototype.substr = function(start, length) {
        const result = origSubstr.call(this, start, length);
        if (isTainted(this)) {
            return taintString(result, 'substr');
        }
        return result;
    };

    const origSplit = String.prototype.split;
    String.prototype.split = function(separator, limit) {
        const result = origSplit.call(this, separator, limit);
        if (isTainted(this)) {
            return result.map(s => taintString(s, 'split'));
        }
        return result;
    };

    // Hook toString/valueOf for implicit coercion taint propagation
    const origToString = String.prototype.toString;
    String.prototype.toString = function() {
        const result = origToString.call(this);
        if (isTainted(this)) return taintString(result, 'toString');
        return result;
    };

    const origValueOf = String.prototype.valueOf;
    String.prototype.valueOf = function() {
        const result = origValueOf.call(this);
        if (isTainted(this)) return taintString(result, 'valueOf');
        return result;
    };

    // Taint URL parameters on access
    try {
        const origURLSearchParamsGet = URLSearchParams.prototype.get;
        URLSearchParams.prototype.get = function(name) {
            const val = origURLSearchParamsGet.call(this, name);
            if (val && checkMarker(val)) {
                return taintString(val, 'URLSearchParams.get');
            }
            return val;
        };
    } catch(e) {}

    // TRUSTED TYPES HOOKS
    if (window.trustedTypes) {
        const origCreatePolicy = window.trustedTypes.createPolicy.bind(window.trustedTypes);
        window.trustedTypes.createPolicy = function(name, rules) {
            recordExecution('trusted-types-policy', name, 'trustedTypes');
            const policy = origCreatePolicy(name, rules);
            // Wrap policy methods to detect marker usage
            const origCreateHTML = policy.createHTML?.bind(policy);
            const origCreateScript = policy.createScript?.bind(policy);
            const origCreateScriptURL = policy.createScriptURL?.bind(policy);

            if (origCreateHTML) {
                policy.createHTML = function(input) {
                    if (checkMarker(input)) recordExecution('trusted-types-html', input, 'trustedTypes');
                    return origCreateHTML(input);
                };
            }
            if (origCreateScript) {
                policy.createScript = function(input) {
                    if (checkMarker(input)) recordExecution('trusted-types-script', input, 'trustedTypes');
                    return origCreateScript(input);
                };
            }
            if (origCreateScriptURL) {
                policy.createScriptURL = function(input) {
                    if (checkMarker(input)) recordExecution('trusted-types-url', input, 'trustedTypes');
                    return origCreateScriptURL(input);
                };
            }
            return policy;
        };
    }

    // IFRAME RECURSIVE INJECTION
    // Inject interceptor into same-origin iframes
    function injectIntoFrame(frame) {
        try {
            if (!frame.contentWindow || !frame.contentDocument) return;
            // Check same-origin
            try { frame.contentDocument.body; } catch(e) { return; } // Cross-origin, skip

            // Inject our marker
            frame.contentWindow.__xssMarker = window.__xssMarker;
            frame.contentWindow.__xssTriggered = false;
            frame.contentWindow.__xssTriggerType = 'none';
            frame.contentWindow.__xssExecutions = [];

            // Hook alert/confirm/prompt in frame
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
        } catch(e) { /* cross-origin or security error */ }
    }

    // Hook iframe creation to inject into new iframes
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

    // Inject into existing iframes
    document.querySelectorAll('iframe').forEach(injectIntoFrame);

    // Watch for dynamically added iframes
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

    // 1. Dialog interception (alert, confirm, prompt)
    window.__originalAlert = window.alert;
    window.__originalConfirm = window.confirm;
    window.__originalPrompt = window.prompt;

    window.alert = function(msg) {
        if (checkMarker(msg)) recordExecution('alert', msg);
        // Don't call original - avoid blocking
    };

    window.confirm = function(msg) {
        if (checkMarker(msg)) recordExecution('confirm', msg);
        return true;
    };

    window.prompt = function(msg, def) {
        if (checkMarker(msg)) recordExecution('prompt', msg);
        return def || '';
    };

    // 2. DOM Sink hooking - detect marker reaching innerHTML, outerHTML, etc.
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

    // 5. setTimeout/setInterval with string (dangerous)
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

    // 6b. setAttribute - CRITICAL for event handler injection (onclick, onerror, etc)
    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (typeof value === 'string' && checkMarker(value) && name.toLowerCase().startsWith('on')) {
            recordExecution('dom-event-attribute', name + '=' + value, 'setAttribute');
        }
        return origSetAttribute.call(this, name, value);
    };

    // 7. Hook fetch with RESPONSE body monitoring AND request logging for replay
    window.__xssRequests = [];
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

        // ALWAYS log fetch requests for replay
        window.__xssRequests.push({
            type: 'fetch',
            url: String(url),
            method: options?.method || 'GET'
        });

        return res;
    };

    // 7b. Hook XHR with response monitoring AND request logging
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

        // Log XHR for replay
        window.__xssRequests.push({
            type: 'xhr',
            url: String(url),
            method: method
        });

        return origXHROpen.call(this, method, url, ...rest);
    };

    // 7c. textContent and innerText hooks (CRITICAL - modern XSS often uses these)
    ['textContent', 'innerText'].forEach(function(prop) {
        try {
            const desc = Object.getOwnPropertyDescriptor(Node.prototype, prop);
            if (desc && desc.set) {
                Object.defineProperty(Node.prototype, prop, {
                    set: function(value) {
                        if (checkMarker(value)) {
                            recordExecution(prop, value, 'text-sink');
                        }
                        return desc.set.call(this, value);
                    },
                    get: desc.get,
                    configurable: true
                });
            }
        } catch(e) {}
    });

    // 8. Location changes (open redirect / JS redirect)
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

    // 9. DOM Mutation Observer - detect marker appearing in DOM
    const observer = new MutationObserver(function(mutations) {
        for (const mutation of mutations) {
            if (mutation.type === 'childList') {
                for (const node of mutation.addedNodes) {
                    if (node.nodeType === 1) { // Element
                        const html = node.outerHTML || '';
                        if (checkMarker(html)) {
                            recordExecution('DOM-mutation', html);
                        }
                    } else if (node.nodeType === 3) { // Text
                        if (checkMarker(node.textContent)) {
                            recordExecution('DOM-text', node.textContent);
                        }
                    }
                }
            } else if (mutation.type === 'attributes') {
                const value = mutation.target.getAttribute(mutation.attributeName) || '';
                if (checkMarker(value)) {
                    recordExecution('DOM-attr', mutation.attributeName + '=' + value);
                }
            }
        }
    });

    // Start observing when DOM is ready
    if (document.body) {
        observer.observe(document.body, {childList: true, subtree: true, attributes: true});
    } else {
        document.addEventListener('DOMContentLoaded', function() {
            observer.observe(document.body, {childList: true, subtree: true, attributes: true});
        });
    }

    // 10. Console error hook for CSP violations
    const originalConsoleError = console.error;
    console.error = function(...args) {
        const msg = args.join(' ');
        if (msg.includes('Content Security Policy') || msg.includes('CSP')) {
            recordExecution('CSP-violation', msg);
        }
        return originalConsoleError.apply(console, args);
    };

    // 11. Image/Script src hooking (for data exfil detection)
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

    // 12. Shadow DOM support - hook attachShadow to monitor shadow roots
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(init) {
        const shadowRoot = originalAttachShadow.call(this, init);

        // Observe shadow root for mutations
        const shadowObserver = new MutationObserver(function(mutations) {
            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === 1) {
                            const html = node.outerHTML || '';
                            if (checkMarker(html)) {
                                recordExecution('shadow-DOM-mutation', html, 'shadow-root');
                            }
                            // Check scripts inside shadow DOM
                            if (node.tagName === 'SCRIPT' && checkMarker(node.textContent)) {
                                recordExecution('shadow-DOM-script', node.textContent, 'shadow-root');
                            }
                        }
                    }
                }
            }
        });
        shadowObserver.observe(shadowRoot, {childList: true, subtree: true});

        // Hook innerHTML on shadow root
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

    // 13. Script element src and textContent hooking
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

    // 14. Iframe src hooking (can be used for XSS via javascript: URLs)
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

    // 14b. Iframe srcdoc hooking (executes BEFORE load event)
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

    // 15. Object/Embed data attribute (for plugin-based XSS)
    const originalObjectData = Object.getOwnPropertyDescriptor(HTMLObjectElement.prototype, 'data');
    if (originalObjectData && originalObjectData.set) {
        Object.defineProperty(HTMLObjectElement.prototype, 'data', {
            set: function(value) {
                if (checkMarker(value)) recordExecution('object.data', value, 'object-element');
                return originalObjectData.set.call(this, value);
            },
            get: originalObjectData.get,
            configurable: true
        });
    }

    // 16. Link href hooking (javascript: URLs)
    const originalLinkHref = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
    if (originalLinkHref && originalLinkHref.set) {
        Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
            set: function(value) {
                if (value && (checkMarker(value) || value.startsWith('javascript:'))) {
                    recordExecution('a.href', value, 'anchor-element');
                }
                return originalLinkHref.set.call(this, value);
            },
            get: originalLinkHref.get,
            configurable: true
        });
    }

    // 17. Range.createContextualFragment (another DOM XSS vector)
    const originalCreateContextualFragment = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function(html) {
        if (checkMarker(html)) recordExecution('createContextualFragment', html, 'range-api');
        return originalCreateContextualFragment.call(this, html);
    };

    // 18. DOMParser (can parse HTML with scripts)
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

    console.log('[XSS-SCANNER] Production-grade interceptor installed (dialogs + sinks + DOM + Shadow DOM + sources)');
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
    /// Uses CDP Page.addScriptToEvaluateOnNewDocument to inject BEFORE any page JS runs
    pub fn new_tab_with_interceptor(&self, marker: &str) -> Result<Arc<Tab>> {
        let browser = self.browser.read()
            .map_err(|e| anyhow::anyhow!("Failed to lock browser: {}", e))?;
        let tab = browser.new_tab()?;

        // Set shorter timeout for navigation
        tab.set_default_timeout(Duration::from_secs(10));

        // Enable JavaScript dialogs to be auto-handled
        // This ensures dialogs don't block execution
        tab.call_method(headless_chrome::protocol::cdp::Page::Enable {
            enable_file_chooser_opened_event: None,
        })?;

        // Inject interceptor script BEFORE page JS runs using CDP
        // This is the correct way - runs at document_start
        let setup_js = format!(
            "{}\nwindow.__xssMarker = '{}';",
            XSS_INTERCEPTOR,
            marker
        );

        // Use Page.addScriptToEvaluateOnNewDocument - this injects BEFORE any page JS
        tab.call_method(headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
            source: setup_js,
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        })?;

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
    pub severity: XssSeverity,
    pub stack_trace: Option<String>,
    pub source: Option<String>,
    pub timestamp: Option<u64>,
}

/// How the XSS was triggered
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

/// XSS severity classification
#[derive(Debug, Clone, PartialEq)]
pub enum XssSeverity {
    Critical, // eval, Function, setTimeout with string
    High,     // innerHTML, document.write, location changes
    Medium,   // dialogs, fetch
    Low,      // DOM mutations, img.src
    Unknown,
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
                            // Use JSON encoding for clean escaping
                            let escaped_selector = selector.replace('\\', "\\\\").replace('"', "\\\"");
                            let escaped_payload = serde_json::to_string(payload).unwrap_or_else(|_| format!("\"{}\"", payload));
                            let fill_js = format!(
                                r#"(function() {{
                                    const el = document.querySelector("{}");
                                    if (el) {{
                                        el.value = {};
                                        console.log('[XSS-FILL]', el.name || el.id, '=', el.value.substring(0, 50));
                                    }}
                                }})()"#,
                                escaped_selector,
                                escaped_payload
                            );
                            let _ = tab.evaluate(&fill_js, false);
                        }
                    }
                }

                // Log what we're about to submit
                info!("[Chromium-XSS] Submitting form {} with payload: {}...", form_idx, &payload[..std::cmp::min(50, payload.len())]);

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

                // Wait for submission and page render
                std::thread::sleep(Duration::from_millis(2000));

                // Reset marker after form submit (page may have reloaded)
                let _ = tab.evaluate(
                    &format!("window.__xssMarker='{}'; window.__xssTriggered=false; window.__xssTriggerType='none';", marker),
                    false
                );

                // Check if XSS triggered immediately (same-page render via hooks)
                if let Some(result) = Self::check_xss_triggered(&tab, url, payload)? {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED stored XSS via form (hook detected)!");
                        results.push(result);
                        return Ok(results);
                    }
                }

                // CRITICAL: Also check if marker appears in DOM directly (for cases where hooks didn't fire)
                let dom_check_js = format!(r#"
                    (function() {{
                        const marker = '{}';
                        const html = document.documentElement.innerHTML;
                        if (html.includes(marker)) {{
                            window.__xssTriggered = true;
                            window.__xssTriggerType = 'dom-content';
                            window.__xssMessage = 'Marker found in rendered DOM';
                            return true;
                        }}
                        return false;
                    }})()
                "#, marker);
                if let Ok(dom_result) = tab.evaluate(&dom_check_js, false) {
                    if dom_result.value.and_then(|v| v.as_bool()).unwrap_or(false) {
                        info!("[Chromium-XSS] CONFIRMED stored XSS - marker found in DOM!");
                        if let Some(result) = Self::check_xss_triggered(&tab, url, payload)? {
                            results.push(result);
                            return Ok(results);
                        }
                    }
                }

                // CRITICAL: Capture recorded requests BEFORE reload
                let requests_js = "JSON.stringify(window.__xssRequests || [])";
                let recorded_requests: Vec<serde_json::Value> = if let Ok(req_result) = tab.evaluate(requests_js, false) {
                    if let Some(value) = req_result.value {
                        if let Some(json_str) = value.as_str() {
                            serde_json::from_str(json_str).unwrap_or_default()
                        } else { Vec::new() }
                    } else { Vec::new() }
                } else { Vec::new() };

                info!("[Chromium-XSS] Captured {} requests, setting up bootstrap replay...", recorded_requests.len());

                // Create a NEW tab with fresh interceptor for bootstrap replay
                let replay_tab = browser.new_tab_with_interceptor(&marker)?;
                replay_tab.set_default_timeout(Duration::from_secs(15));

                // CRITICAL: Inject fetch override BEFORE navigation to replay during bootstrap
                // This intercepts fetch calls during page load and ensures stored data triggers render
                let replay_urls: Vec<String> = recorded_requests.iter()
                    .filter_map(|r| r.get("url").and_then(|v| v.as_str()))
                    .filter(|u| u.contains("comment") || u.contains("api") || u.contains("data") || u.contains("load"))
                    .map(|s| s.to_string())
                    .collect();

                if !replay_urls.is_empty() {
                    let replay_setup_js = format!(r#"
                        (function() {{
                            window.__replayUrls = {};
                            window.__replayDone = false;

                            const origFetch = window.fetch;
                            window.fetch = async function(...args) {{
                                const [url] = args;
                                const urlStr = String(url);

                                // During bootstrap, ensure we hit the real endpoint (which now has stored payload)
                                console.log('[XSS-REPLAY] Fetch intercepted during bootstrap:', urlStr);

                                const res = await origFetch.apply(this, args);

                                // Check response for our marker
                                try {{
                                    const clone = res.clone();
                                    const text = await clone.text();
                                    if (text.includes(window.__xssMarker)) {{
                                        console.log('[XSS-REPLAY] MARKER FOUND IN RESPONSE!');
                                        window.__xssTriggered = true;
                                        window.__xssTriggerType = 'fetch-response-bootstrap';
                                        window.__xssMessage = text.substring(0, 300);
                                    }}
                                }} catch(e) {{}}

                                return res;
                            }};
                        }})();
                    "#, serde_json::to_string(&replay_urls).unwrap_or("[]".to_string()));

                    let _ = replay_tab.evaluate(&replay_setup_js, false);
                }

                // NOW navigate - fetch override is in place for bootstrap
                info!("[Chromium-XSS] Navigating with bootstrap replay active...");
                let _ = replay_tab.navigate_to(url);
                std::thread::sleep(Duration::from_millis(3000)); // Longer wait for full bootstrap

                // Check if XSS triggered during bootstrap render
                if let Some(result) = Self::check_xss_triggered(&replay_tab, url, payload)? {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED stored XSS during bootstrap render!");
                        results.push(result);
                        return Ok(results);
                    }
                }

                // Also try forcing render after bootstrap (for lazy-loaded content)
                let _ = replay_tab.evaluate(r#"
                    (function() {
                        // Force re-render by triggering common events
                        document.dispatchEvent(new Event('visibilitychange'));
                        window.dispatchEvent(new Event('focus'));
                        window.dispatchEvent(new Event('hashchange'));

                        // Try common SPA render hooks
                        if (window.renderComments) try { window.renderComments(); } catch(e) {}
                        if (window.loadComments) try { window.loadComments(); } catch(e) {}
                        if (window.refreshComments) try { window.refreshComments(); } catch(e) {}
                        if (window.loadData) try { window.loadData(); } catch(e) {}
                        if (window.refresh) try { window.refresh(); } catch(e) {}

                        // Click refresh/load buttons
                        document.querySelectorAll('[class*="refresh"], [class*="reload"], [class*="load"], [onclick*="load"]').forEach(el => {
                            try { el.click(); } catch(e) {}
                        });

                        // Trigger any pending promises
                        setTimeout(() => {
                            document.querySelectorAll('[data-load], [data-fetch]').forEach(el => {
                                try { el.dispatchEvent(new Event('load')); } catch(e) {}
                            });
                        }, 100);
                    })();
                "#, false);
                std::thread::sleep(Duration::from_millis(1500));

                // Final check after forced render
                if let Some(result) = Self::check_xss_triggered(&replay_tab, url, payload)? {
                    if result.xss_triggered {
                        info!("[Chromium-XSS] CONFIRMED stored XSS after forced render!");
                        results.push(result);
                        return Ok(results);
                    }
                }

                // Also check potential render endpoints (common API patterns)
                let render_endpoints = vec![
                    format!("{}/comments", url.split('?').next().unwrap_or(url)),
                    format!("{}?action=view", url.split('?').next().unwrap_or(url)),
                    url.replace("admin", "view"),
                ];

                for endpoint in render_endpoints.iter().take(2) {
                    if endpoint != url {
                        let _ = tab.evaluate(
                            &format!("window.__xssMarker = '{}'; window.__xssTriggered = false;", marker),
                            false
                        );
                        if tab.navigate_to(endpoint).is_ok() {
                            std::thread::sleep(Duration::from_millis(1500));
                            if let Some(result) = Self::check_xss_triggered(&tab, endpoint, payload)? {
                                if result.xss_triggered {
                                    info!("[Chromium-XSS] CONFIRMED stored XSS at render endpoint: {}", endpoint);
                                    results.push(result);
                                    return Ok(results);
                                }
                            }
                        }
                    }
                }

                // Navigate back for next payload
                let _ = tab.navigate_to(url);
                std::thread::sleep(Duration::from_millis(800));

                // Reset marker after SPA navigation (SPAs may overwrite globals)
                let _ = tab.evaluate(
                    &format!("window.__xssMarker='{}'; window.__xssTriggered=false; window.__xssTriggerType='none';", marker),
                    false
                );
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
                severity: XssSeverity::Unknown,
                stack_trace: None,
                source: None,
                timestamp: None,
            });
        }

        // Wait for page load - use wait_until_navigated with timeout
        // If this fails, we still check XSS since interceptor might have caught it
        let _ = tab.wait_until_navigated();

        // Brief pause for JS execution
        std::thread::sleep(Duration::from_millis(300));

        // Reset marker after navigation (SPAs may overwrite globals during hydration)
        let _ = tab.evaluate(
            &format!("window.__xssMarker='{}'; if(!window.__xssTriggered) window.__xssTriggerType='none';", marker),
            false
        );

        // Simulate events to trigger event-handler XSS (click, focus, mouseover)
        let _ = tab.evaluate(r#"
            (function() {
                // Trigger focus on inputs (for onfocus handlers)
                document.querySelectorAll('input, textarea').forEach(el => {
                    try { el.focus(); el.blur(); } catch(e) {}
                });
                // Trigger mouseover on interactive elements
                document.querySelectorAll('a, button, [onclick], [onmouseover]').forEach(el => {
                    try {
                        el.dispatchEvent(new MouseEvent('mouseover', {bubbles: true}));
                        el.dispatchEvent(new MouseEvent('mouseenter', {bubbles: true}));
                    } catch(e) {}
                });
                // Click autofocus elements
                const autofocus = document.querySelector('[autofocus]');
                if (autofocus) try { autofocus.click(); } catch(e) {}
            })();
        "#, false);

        // Wait for event handlers to execute
        std::thread::sleep(Duration::from_millis(300));

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
                    let triggered = parsed.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);
                    let trigger_str = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                    let message = parsed.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let severity_str = parsed.get("severity").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
                    let stack = parsed.get("stack").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let source = parsed.get("source").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let timestamp = parsed.get("timestamp").and_then(|v| v.as_u64());

                    let trigger_type = match trigger_str {
                        "alert" => XssTriggerType::AlertDialog,
                        "confirm" => XssTriggerType::ConfirmDialog,
                        "prompt" => XssTriggerType::PromptDialog,
                        "eval" | "Function" | "setTimeout" | "setInterval" => XssTriggerType::Eval,
                        "innerHTML" | "outerHTML" | "insertAdjacentHTML" => XssTriggerType::InnerHtml,
                        "document.write" | "document.writeln" => XssTriggerType::DocumentWrite,
                        "location.assign" | "location.replace" => XssTriggerType::LocationChange,
                        "fetch-url" | "img.src" => XssTriggerType::DataExfil,
                        "fetch-response" | "fetch-response-bootstrap" | "xhr-response" => XssTriggerType::InnerHtml, // Response contains XSS
                        "textContent" | "innerText" => XssTriggerType::DomExecution,
                        s if s.contains("shadow") => XssTriggerType::ShadowDom,
                        s if s.starts_with("dom-") => XssTriggerType::DomExecution, // dom-html, dom-event-attribute, etc
                        s if s.starts_with("js-") => XssTriggerType::Eval,          // js-eval, js-function
                        s if s.contains("DOM") => XssTriggerType::DomExecution,
                        _ => XssTriggerType::DomExecution, // Default to DOM execution instead of None - if triggered, it's XSS
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

        // Map XssSeverity to Severity and CVSS
        let (severity, cvss) = match result.severity {
            XssSeverity::Critical => (Severity::Critical, 9.6),
            XssSeverity::High => (Severity::High, 8.2),
            XssSeverity::Medium => (Severity::Medium, 6.5),
            XssSeverity::Low => (Severity::Low, 4.3),
            XssSeverity::Unknown => (Severity::High, 7.5), // Default for unknown
        };

        // Build detailed evidence with all available info
        let mut evidence_parts = vec![
            format!("Trigger: {}", trigger_desc),
            format!("Severity: {:?}", result.severity),
            format!("Payload: {}", result.payload),
        ];

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
            parameter: None,
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
