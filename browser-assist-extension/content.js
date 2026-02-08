// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Browser-Assist Content Script
 *
 * Injected into every page to detect client-side vulnerabilities:
 * - DOM XSS with taint tracking
 * - Prototype pollution
 * - JavaScript secrets
 * - Session/auth extraction
 * - API endpoint discovery
 * - Framework detection
 */

(function() {
  'use strict';

  // Avoid double injection
  if (window.__lkI) return;
  window.__lkI = true;

  // ============================================================
  // LICENSE CHECK - Block scanning features for unlicensed users
  // ============================================================

  // Check license state from background service worker.
  // If not licensed, the content script will not inject any scanners.
  let __lonkeroLicensed = false;

  let __lonkeroLicenseKey = null;

  function _t(event, props) {
    try { chrome.runtime.sendMessage({ type: 'trackEvent', event, props }); } catch {}
  }

  function checkContentLicense() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: 'checkLicense' }, (response) => {
          if (chrome.runtime.lastError) {
            resolve(false);
            return;
          }
          if (response && response.licensed && response.key) {
            __lonkeroLicenseKey = response.key;
          }
          resolve(response && response.licensed);
        });
      } catch (e) {
        resolve(false);
      }
    });
  }

  /**
   * Inject the license key into page context so scanner files can
   * independently validate against the Bountyy license server.
   * Each scanner does its own server-side check - stripping the
   * content.js check alone is not enough.
   */
  let __msgNonce = null;

  let __evtChannel = null; // Per-session random event channel name

  function injectLicenseKey() {
    if (!__lonkeroLicenseKey) return;
    try {
      // Generate per-session nonce for message authentication
      const arr = new Uint8Array(8);
      crypto.getRandomValues(arr);
      __msgNonce = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');

      // Generate per-session random channel name for postMessage
      const ch = new Uint8Array(6);
      crypto.getRandomValues(ch);
      __evtChannel = '_e' + Array.from(ch, b => b.toString(36).padStart(2, '0')).join('').slice(0, 10);

      const el = document.createElement('div');
      el.id = '__lk_c';
      el.style.display = 'none';
      el.dataset.v = __lonkeroLicenseKey;
      el.dataset.n = __msgNonce;
      el.dataset.e = __evtChannel;
      (document.head || document.documentElement).appendChild(el);
    } catch (e) {
      // Silently fail
    }
  }

  // ============================================================
  // SCOPE CHECK - Only run on main frame, not ad/tracking iframes
  // ============================================================

  // Skip if we're in an iframe (not the top window)
  const isMainFrame = window === window.top;

  // Known third-party/ad domains to NEVER scan
  const SKIP_DOMAINS = new Set([
    // Ad networks
    'adnxs.com', 'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'adsrvr.org', 'adform.net', 'criteo.com', 'taboola.com', 'outbrain.com',
    'openx.net', 'pubmatic.com', 'rubiconproject.com', 'casalemedia.com',
    'advertising.com', 'bidswitch.net', 'media.net', 'amazon-adsystem.com',
    'ib.adnxs.com', 'acdn.adnxs.com',
    // Analytics & Tracking
    'google-analytics.com', 'googletagmanager.com', 'facebook.net', 'facebook.com',
    'twitter.com', 'linkedin.com', 'hotjar.com', 'segment.com', 'mixpanel.com',
    'amplitude.com', 'heapanalytics.com', 'fullstory.com', 'logrocket.com',
    'mouseflow.com', 'crazyegg.com', 'luckyorange.com', 'clicktale.net',
    'userreport.com', 'ebxcdn.com',
    // Consent/Privacy
    'cookiebot.com', 'onetrust.com', 'trustarc.com', 'quantcast.com',
    'consentmanager.net', 'usercentrics.com', 'cookielaw.org', 'cookiepro.com',
    'privacy-mgmt.com', 'sourcepoint.com', 'sp-prod.net',
    // CDNs (don't scan these)
    'cloudflare.com', 'cloudfront.net', 'akamaized.net', 'fastly.net',
    'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'bootstrapcdn.com',
    // Social widgets
    'platform.twitter.com', 'connect.facebook.net', 'platform.linkedin.com',
    // Chat widgets
    'intercom.io', 'zendesk.com', 'crisp.chat', 'tawk.to', 'drift.com',
    // Other common third-party
    'recaptcha.net', 'gstatic.com', 'google.com', 'googleapis.com',
  ]);

  // Check if current hostname should be skipped
  function shouldSkipDomain(hostname) {
    const host = hostname.toLowerCase();
    // Direct match
    if (SKIP_DOMAINS.has(host)) return true;
    // Subdomain match (e.g., acdn.adnxs.com matches adnxs.com)
    for (const domain of SKIP_DOMAINS) {
      if (host === domain || host.endsWith('.' + domain)) return true;
    }
    return false;
  }

  // If we're in an iframe on a third-party domain, exit immediately
  if (!isMainFrame && shouldSkipDomain(location.hostname)) {
    console.log('[Lonkero] Skipping third-party iframe:', location.hostname);
    return;
  }

  const findings = [];
  const discoveredEndpoints = new Set();
  const discoveredSecrets = [];

  // ============================================================
  // SAFE MESSAGE SENDING (handles extension context invalidation)
  // ============================================================

  function safeSendMessage(message, callback = null) {
    try {
      // Check if extension context is still valid
      if (!chrome.runtime?.id) {
        console.warn('[Lonkero] Extension context invalidated');
        return;
      }

      const promise = chrome.runtime.sendMessage(message);

      if (callback) {
        promise.then(callback).catch(e => {
          console.warn('[Lonkero] Message send failed:', e.message);
        });
      } else {
        promise.catch(e => {
          // Silently handle - context was invalidated
        });
      }
    } catch (e) {
      // Synchronous error - extension context already invalid
      console.warn('[Lonkero] Extension context error');
    }
  }

  // ============================================================
  // DOM XSS TAINT TRACKING
  // ============================================================

  // Sources: where untrusted data comes from
  const TAINT_SOURCES = {
    'location.hash': () => location.hash,
    'location.search': () => location.search,
    'location.href': () => location.href,
    'location.pathname': () => location.pathname,
    'document.URL': () => document.URL,
    'document.documentURI': () => document.documentURI,
    'document.referrer': () => document.referrer,
    'document.cookie': () => document.cookie,
    'window.name': () => window.name,
  };

  // Sinks: dangerous functions that can cause XSS
  const DANGEROUS_SINKS = [
    'innerHTML', 'outerHTML', 'insertAdjacentHTML',
    'document.write', 'document.writeln',
    'eval', 'setTimeout', 'setInterval', 'Function',
    'setAttribute', 'src', 'href', 'action',
  ];

  // Track tainted values
  const taintedValues = new Map();

  // Check sources for interesting values
  function checkSources() {
    // False positive exclusions (common cookie/config patterns)
    const falsePositivePatterns = [
      /consent=/i, /cookieyes/i, /cookie-consent/i, /gdpr/i,
      /analytics=/i, /functional=/i, /necessary=/i, /advertisement=/i,
      /tracking=/i, /preferences=/i, /^[a-z_]+=(?:yes|no|true|false);?$/i,
    ];

    for (const [name, getter] of Object.entries(TAINT_SOURCES)) {
      try {
        const value = getter();
        if (value && value.length > 0) {
          // Look for potential XSS payloads in sources
          // Use stricter patterns to avoid false positives
          const xssPatterns = [
            { pattern: /<script/i, name: 'script_tag' },
            { pattern: /javascript:/i, name: 'javascript_uri' },
            // Stricter event handler check - must be preceded by space/quote/< or start of string
            { pattern: /(?:^|[\s"'<])on(click|load|error|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=/i, name: 'event_handler' },
            { pattern: /\beval\s*\(/i, name: 'eval_call' },
            { pattern: /\balert\s*\(/i, name: 'alert_call' },
            // Only flag document. if followed by suspicious methods
            { pattern: /document\.(write|cookie|location|domain)/i, name: 'document_access' },
          ];

          for (const { pattern, name: patternName } of xssPatterns) {
            if (pattern.test(value)) {
              // Check if this is likely a false positive
              const isFalsePositive = falsePositivePatterns.some(fp => fp.test(value));

              // Skip cookie consent strings for on\w+= pattern
              if (patternName === 'event_handler' && isFalsePositive) {
                continue;
              }

              reportFinding('DOM_XSS_SOURCE', {
                source: name,
                value: value.substring(0, 200),
                pattern: pattern.toString(),
                patternType: patternName,
                url: location.href,
              });
            }
          }

          // Track this value
          taintedValues.set(value, name);
        }
      } catch (e) {}
    }
  }

  // Monitor innerHTML assignments
  const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {
    set: function(value) {
      // Check if this value came from a tainted source
      const valueStr = String(value);
      for (const [taintedValue, source] of taintedValues) {
        if (valueStr.includes(taintedValue)) {
          reportFinding('DOM_XSS_SINK', {
            sink: 'innerHTML',
            source: source,
            element: this.tagName,
            valuePreview: valueStr.substring(0, 200),
            url: location.href,
          });
        }
      }

      // Check for direct XSS patterns
      if (/<script|javascript:|on\w+=/i.test(valueStr)) {
        reportFinding('DOM_XSS_POTENTIAL', {
          sink: 'innerHTML',
          element: this.tagName,
          valuePreview: valueStr.substring(0, 200),
          url: location.href,
        });
      }

      return originalInnerHTML.set.call(this, value);
    },
    get: originalInnerHTML.get,
  });

  // Monitor document.write
  const originalWrite = document.write;
  document.write = function(content) {
    const contentStr = String(content);
    if (/<script|javascript:|on\w+=/i.test(contentStr)) {
      reportFinding('DOM_XSS_SINK', {
        sink: 'document.write',
        valuePreview: contentStr.substring(0, 200),
        url: location.href,
      });
    }
    return originalWrite.apply(this, arguments);
  };

  // Monitor eval
  const originalEval = window.eval;
  window.eval = function(code) {
    reportFinding('DANGEROUS_EVAL', {
      codePreview: String(code).substring(0, 200),
      url: location.href,
    });
    return originalEval.apply(this, arguments);
  };

  // ============================================================
  // PROTOTYPE POLLUTION DETECTION
  // ============================================================

  // Monitor Object.prototype for pollution
  const protoProps = new Set(Object.getOwnPropertyNames(Object.prototype));

  function checkPrototypePollution() {
    const currentProps = Object.getOwnPropertyNames(Object.prototype);
    for (const prop of currentProps) {
      if (!protoProps.has(prop)) {
        reportFinding('PROTOTYPE_POLLUTION', {
          property: prop,
          value: String(Object.prototype[prop]).substring(0, 100),
          url: location.href,
        });
      }
    }

    // Check for common pollution gadgets
    const gadgets = ['__proto__', 'constructor', 'prototype'];
    for (const gadget of gadgets) {
      if (location.href.includes(gadget) || location.hash.includes(gadget)) {
        reportFinding('PROTOTYPE_POLLUTION_ATTEMPT', {
          gadget: gadget,
          url: location.href,
        });
      }
    }
  }

  // ============================================================
  // JAVASCRIPT SECRET SCANNER
  // ============================================================

  const SECRET_PATTERNS = [
    // AWS - Access keys have a very specific format (AKIA prefix + 16 uppercase alphanumeric)
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey)["'\s:=]+([A-Za-z0-9/+=]{40})/g },

    // JWT - very specific three-part base64 format
    { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g },

    // Bearer tokens in code/config (not just JWT)
    { name: 'Bearer Token', pattern: /[Bb]earer\s+[a-zA-Z0-9_-]{20,}/g },
    { name: 'Authorization Header', pattern: /[Aa]uthorization["'\s:=]+["']?Bearer\s+[a-zA-Z0-9_.-]{20,}/g },

    // Google - specific prefixes
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
    // Note: Google OAuth client IDs are PUBLIC (not secrets) - only flag client secrets
    { name: 'Google OAuth Secret', pattern: /(?:client_secret|clientSecret)["'\s:=]+["']?([a-zA-Z0-9_-]{24})/gi },

    // reCAPTCHA - only detect SECRET keys (site keys are public, not security issues)
    { name: 'reCAPTCHA Secret', pattern: /(?:secret|secretKey|recaptcha.*secret)["'\s:=]+["']?(6L[a-zA-Z0-9_-]{38})/gi },

    // Note: GTM, GA, GA4 IDs are PUBLIC tracking IDs - not security issues, skipped

    // GitHub - specific prefixes (gh followed by specific letter)
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g },

    // Stripe - specific prefixes
    { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24,}/g },

    // Mapbox tokens
    { name: 'Mapbox Secret', pattern: /sk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
    { name: 'Mapbox Public Token', pattern: /pk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: 'info', note: 'Public token - not a secret but may reveal API usage' },

    // Private Keys - very specific markers
    { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },

    // Slack - specific format (xox followed by specific letter)
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{10,}/g },

    // Firebase - specific domain
    { name: 'Firebase URL', pattern: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/g },

    // Twilio - specific format
    { name: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/g },
    { name: 'Twilio Account SID', pattern: /AC[a-f0-9]{32}/g },

    // SendGrid - specific format
    { name: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}/g },

    // Mailchimp - specific format
    { name: 'Mailchimp API Key', pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g },

    // Heroku
    { name: 'Heroku API Key', pattern: /[hH]eroku.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g },

    // npm
    { name: 'npm Token', pattern: /npm_[a-zA-Z0-9]{36}/g },

    // Discord
    { name: 'Discord Token', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g },
    { name: 'Discord Webhook', pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g },

    // Shopify
    { name: 'Shopify Token', pattern: /shpat_[a-fA-F0-9]{32}/g },
    { name: 'Shopify Shared Secret', pattern: /shpss_[a-fA-F0-9]{32}/g },

    // Square
    { name: 'Square Access Token', pattern: /sq0atp-[0-9A-Za-z_-]{22}/g },
    { name: 'Square OAuth Secret', pattern: /sq0csp-[0-9A-Za-z_-]{43}/g },

    // Algolia
    { name: 'Algolia API Key', pattern: /[a-f0-9]{32}(?=.*algolia)/gi },

    // OpenAI
    { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48}/g },

    // Finnish HETU (henkilötunnus / personal identity code)
    // Format: DDMMYY[-+A]XXXC where C is check char from 0-9 or ABCDEFHJKLMNPRSTUVWXY
    { name: 'Finnish HETU', pattern: /\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(\d{2})[-+A]\d{3}[0-9A-Y]\b/g },

    // Finnish business ID (Y-tunnus)
    // Format: 1234567-8 (7 digits, dash, check digit)
    { name: 'Finnish Y-tunnus', pattern: /\b\d{7}-\d\b/g },

    // IBAN (International Bank Account Number) - Finnish and others
    { name: 'IBAN', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g },

    // Credit card numbers - require context (not just raw numbers)
    // Look for card numbers near keywords like "card", "cc", "pan", "payment"
    { name: 'Credit Card', pattern: /(?:card|cc|pan|payment|credit|visa|master|amex)["'\s:=_-]*(?:number|num|no)?["'\s:=_-]*(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})/gi },

    // Generic API key patterns (last resort - high false positive but catches unknown services)
    { name: 'API Key (Generic)', pattern: /(?:api[_-]?key|apikey|api_secret)["'\s:=]+["']?([a-zA-Z0-9_-]{20,})/gi },
  ];

  function scanForSecrets(content, source) {
    for (const { name, pattern, severity, note } of SECRET_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          // Avoid duplicates
          const key = `${name}:${match.substring(0, 20)}`;
          if (!discoveredSecrets.includes(key)) {
            discoveredSecrets.push(key);
            // Use different finding type for info-level items
            const findingType = severity === 'info' ? 'KEY_DETECTED' : 'SECRET_EXPOSED';
            reportFinding(findingType, {
              type: name,
              value: match,
              source: source,
              url: location.href,
              severity: severity || 'high',
              note: note || null,
            });
          }
        }
      }
    }
  }

  // Scan inline scripts
  function scanInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, i) => {
      const content = script.textContent;
      const source = `inline-script-${i}`;
      scanForSecrets(content, source);
      scanForCloudStorage(content, source);
      scanForGraphQL(content, source);
    });

    // Also scan the HTML for cloud storage URLs in attributes
    scanForCloudStorage(document.documentElement.outerHTML, 'html');

    // Scan iframes and their src URLs for API keys
    scanIframeUrls();
  }

  // Scan iframe URLs and other embedded URLs for keys
  function scanIframeUrls() {
    // Scan iframe sources
    const iframes = document.querySelectorAll('iframe[src]');
    iframes.forEach(iframe => {
      scanForSecrets(iframe.src, 'iframe-url');
    });

    // Scan script src URLs
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      scanForSecrets(script.src, 'script-url');
    });

    // Scan link href URLs
    const links = document.querySelectorAll('link[href]');
    links.forEach(link => {
      scanForSecrets(link.href, 'link-url');
    });

    // Scan all URLs in the page HTML (catches things like recaptcha URLs)
    const urlPattern = /https?:\/\/[^\s"'<>]+/g;
    const html = document.documentElement.outerHTML;
    const urls = html.match(urlPattern) || [];
    urls.forEach(url => {
      scanForSecrets(url, 'page-url');
    });
  }

  // Scan loaded JS files (first-party only)
  function scanExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      const src = script.src;
      // Only scan first-party scripts
      if (src && src.startsWith(location.origin)) {
        fetch(src)
          .then(r => r.text())
          .then(content => {
            scanForSecrets(content, src);
            scanForCloudStorage(content, src);
            scanForGraphQL(content, src);
          })
          .catch(() => {});
      }
    });
  }

  // ============================================================
  // SESSION & AUTH EXTRACTION
  // ============================================================

  // Consent/analytics tools that use auth-like naming but aren't auth
  const CONSENT_ANALYTICS_PATTERNS = [
    // Consent management platforms
    /^_sp_/i, /^sp_/i, // SourcePoint
    /sourcepoint/i,
    /consent/i, /gdpr/i, /ccpa/i, /privacy/i,
    /cookieyes/i, /cookiebot/i, /onetrust/i, /trustarc/i,
    /quantcast/i, /consentmanager/i, /usercentrics/i,
    // Analytics
    /permutive/i, /segment/i, /amplitude/i, /mixpanel/i,
    /heap/i, /hotjar/i, /fullstory/i, /logrocket/i,
    /google.*analytics/i, /^_ga/i, /^_gid/i, /gtm/i,
    /facebook/i, /fbp/i, /^_fbp/i,
    // Browser/device IDs (not user auth)
    /bsid/i, /browser.*id/i, /device.*id/i, /visitor.*id/i,
    /fingerprint/i, /^fp_/i,
    // Ad tech
    /^_gcl/i, /doubleclick/i, /adsense/i, /adwords/i,
    // Feature flags / experiments
    /optimizely/i, /launchdarkly/i, /split/i, /^experiment/i,
  ];

  function isConsentOrAnalytics(name) {
    return CONSENT_ANALYTICS_PATTERNS.some(pattern => pattern.test(name));
  }

  function extractSessionData() {
    const sessionData = {
      cookies: {},
      localStorage: {},
      sessionStorage: {},
      authHeaders: [],
    };

    // Cookies
    document.cookie.split(';').forEach(cookie => {
      const [name, ...valueParts] = cookie.trim().split('=');
      const value = valueParts.join('=');
      if (name) {
        const trimmedName = name.trim();
        sessionData.cookies[trimmedName] = value;

        // Flag auth-related cookies (but exclude consent/analytics)
        if (/session|token|auth|jwt|sid|csrf/i.test(trimmedName) && !isConsentOrAnalytics(trimmedName)) {
          // Additional check: must look like actual auth (not just "bsid" = browser session)
          const looksLikeAuth = /^(auth|jwt|access|refresh|api|bearer)/i.test(trimmedName) ||
                               /(_token|_jwt|_auth|_key)$/i.test(trimmedName) ||
                               (trimmedName.toLowerCase() === 'session' || trimmedName.toLowerCase() === 'sessionid');
          if (looksLikeAuth) {
            reportFinding('AUTH_COOKIE', {
              name: trimmedName,
              httpOnly: false, // If we can read it, it's not httpOnly
              url: location.href,
            });
          }
        }
      }
    });

    // LocalStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        sessionData.localStorage[key] = value;

        // Skip consent/analytics keys
        if (isConsentOrAnalytics(key)) continue;

        // Check for tokens - must have auth-like key AND auth-like value
        const hasAuthKey = /token|auth|jwt|access|refresh|bearer|api[_-]?key/i.test(key);
        const hasAuthValue = /^eyJ/.test(value) || // JWT
                            /^[a-f0-9]{32,}$/i.test(value) || // Hex token
                            /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/i.test(value); // Token-like

        if (hasAuthKey && hasAuthValue) {
          reportFinding('AUTH_LOCALSTORAGE', {
            key: key,
            valuePreview: value.substring(0, 50),
            url: location.href,
          });
        }
      }
    } catch (e) {}

    // SessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        sessionData.sessionStorage[key] = value;
      }
    } catch (e) {}

    return sessionData;
  }

  // ============================================================
  // API ENDPOINT DISCOVERY
  // ============================================================
  // Note: fetch/XHR interception is now injected into page context via injectRequestInterceptors()

  // Static file extensions to ignore
  const STATIC_EXTENSIONS = /\.(js|mjs|cjs|css|scss|less|png|jpg|jpeg|gif|svg|ico|webp|avif|woff|woff2|ttf|eot|otf|mp4|webm|mp3|wav|ogg|pdf|map|json|xml|txt|md|yml|yaml|toml)$/i;

  // Check if path is static (more comprehensive check)
  function isStaticPath(pathname) {
    // Next.js paths
    if (pathname.includes('/_next/')) return true;
    if (pathname.includes('/__next/')) return true;
    // Nuxt.js paths
    if (pathname.includes('/_nuxt/')) return true;
    // Webpack paths
    if (pathname.includes('/__webpack')) return true;
    if (pathname.includes('/chunks/')) return true;
    // Static directories at root
    if (/^\/(static|assets|public|dist|build|vendor|lib|fonts|images|img|media|node_modules)\//i.test(pathname)) return true;
    // Polyfills and legacy bundles
    if (/polyfill.*\.js$/i.test(pathname)) return true;
    if (/\.legacy\.js$/i.test(pathname)) return true;
    // Well-known
    if (pathname.startsWith('/.well-known/')) return true;
    return false;
  }

  // Comprehensive third-party domains to skip (from JS miner)
  const THIRD_PARTY_DOMAINS = new Set([
    // Analytics & Tracking
    'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
    'googlesyndication.com', 'doubleclick.net', 'analytics.google.com',
    'cloudflareinsights.com', 'hotjar.com', 'segment.com', 'segment.io',
    'mixpanel.com', 'amplitude.com', 'heap.io', 'heapanalytics.com',
    'plausible.io', 'fathom.com', 'matomo.org', 'piwik.pro',
    // Consent & Privacy
    'cookiebot.com', 'onetrust.com', 'cookielaw.org', 'trustarc.com',
    'quantcast.com', 'consentmanager.net', 'usercentrics.com',
    // CDNs & Libraries
    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'polyfill.io',
    'code.jquery.com', 'ajax.googleapis.com', 'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
    'use.fontawesome.com', 'kit.fontawesome.com', 'use.typekit.net',
    // Chat & Support Widgets
    'intercom.io', 'intercomcdn.com', 'crisp.chat', 'zendesk.com',
    'zdassets.com', 'livechatinc.com', 'tawk.to', 'freshdesk.com', 'drift.com',
    // Social & Sharing
    'facebook.net', 'fbcdn.net', 'twitter.com', 'platform.twitter.com',
    'linkedin.com', 'ads-twitter.com', 'connect.facebook.net',
    'platform.linkedin.com', 'widgets.pinterest.com',
    // Ads & Marketing
    'adsrvr.org', 'adform.net', 'criteo.com', 'taboola.com', 'outbrain.com',
    'amazon-adsystem.com', 'bat.bing.com', 'ads.google.com',
    // Payment (public SDKs)
    'js.stripe.com', 'checkout.stripe.com', 'js.braintreegateway.com',
    'www.paypal.com', 'www.paypalobjects.com',
    // Maps & Utilities
    'maps.googleapis.com', 'maps.google.com', 'api.mapbox.com',
    // Monitoring (public)
    'browser.sentry-cdn.com', 'js.sentry-cdn.com', 'cdn.ravenjs.com',
    'rum.hlx.page', 'cdn.speedcurve.com',
    // Other common third-party
    'recaptcha.net', 'www.google.com/recaptcha', 'hcaptcha.com',
    'gstatic.com', 'cloudflare.com', 'challenges.cloudflare.com',
    'static.cloudflareinsights.com', 'cdn.cookielaw.org',
  ]);

  // Documentation domains to skip
  const DOC_DOMAINS = new Set([
    'nextjs.org', 'reactjs.org', 'vuejs.org', 'angular.io', 'nodejs.org',
    'developer.mozilla.org', 'docs.github.com', 'stackoverflow.com',
    'medium.com', 'dev.to', 'w3.org', 'json-schema.org', 'schema.org',
    'npmjs.com', 'github.com', 'gitlab.com', 'bitbucket.org',
  ]);

  // Check if hostname is third-party
  function isThirdParty(hostname) {
    const host = hostname.toLowerCase();
    // Direct match
    if (THIRD_PARTY_DOMAINS.has(host)) return true;
    if (DOC_DOMAINS.has(host)) return true;
    // Subdomain match
    for (const domain of THIRD_PARTY_DOMAINS) {
      if (host.endsWith('.' + domain)) return true;
    }
    for (const domain of DOC_DOMAINS) {
      if (host.endsWith('.' + domain)) return true;
    }
    return false;
  }

  function discoverEndpoint(url, method, source) {
    try {
      // Skip data URIs and blob URLs early
      if (url.startsWith('data:') || url.startsWith('blob:')) return;

      const parsed = new URL(url, location.origin);
      const pathname = parsed.pathname;
      const hostname = parsed.hostname;

      // Skip internal Lonkero API traffic
      if (hostname === atob('bG9ua2Vyby5ib3VudHl5LmZp')) return;

      // Skip static files by extension
      if (STATIC_EXTENSIONS.test(pathname)) return;

      // Skip static paths (framework bundles, assets, etc.)
      if (isStaticPath(pathname)) return;

      // Skip third-party domains (CDNs, analytics, widgets, etc.)
      if (isThirdParty(hostname)) return;

      // Skip if hostname is completely different from current page (cross-origin non-API)
      const currentHost = location.hostname;
      if (hostname !== currentHost && !hostname.endsWith('.' + currentHost)) {
        // Only allow cross-origin if it looks like an API
        if (!/\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/rpc\//i.test(pathname)) {
          return;
        }
      }

      // Detect API patterns
      const isApi = /\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/rpc\/|\/query|\/mutation/i.test(pathname);
      const hasQueryParams = parsed.search.length > 1;
      const isDocument = /\.(html?|php|aspx?|jsp)$/i.test(pathname);
      const hasFileExtension = /\.[a-z]{2,5}$/i.test(pathname);

      // Only report if it's likely an API endpoint
      const shouldReport = isApi || hasQueryParams || (!hasFileExtension && !isDocument && pathname !== '/');

      if (!shouldReport) return;

      const endpoint = `${method} ${pathname}`;

      if (!discoveredEndpoints.has(endpoint)) {
        discoveredEndpoints.add(endpoint);

        safeSendMessage({
          type: 'endpointDiscovered',
          endpoint: {
            method: method,
            url: parsed.href,
            path: pathname,
            isApi: isApi,
            params: parsed.search ? Object.fromEntries(parsed.searchParams) : null,
            source: source,
            origin: location.href,
          }
        });
      }
    } catch (e) {}
  }

  // ============================================================
  // FRAMEWORK DETECTION
  // ============================================================

  function detectFrameworks() {
    const frameworks = [];

    // React
    if (window.React || document.querySelector('[data-reactroot]') ||
        document.querySelector('[data-reactid]') || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      frameworks.push({ name: 'React', version: window.React?.version || 'unknown' });
    }

    // Vue
    if (window.Vue || document.querySelector('[data-v-]') || window.__VUE__) {
      frameworks.push({ name: 'Vue', version: window.Vue?.version || 'unknown' });
    }

    // Angular
    if (window.ng || document.querySelector('[ng-app]') ||
        document.querySelector('[ng-controller]') || window.angular) {
      frameworks.push({ name: 'Angular', version: window.angular?.version?.full || 'unknown' });
    }

    // Next.js
    if (window.__NEXT_DATA__ || document.querySelector('#__next')) {
      const nextData = window.__NEXT_DATA__;
      frameworks.push({
        name: 'Next.js',
        version: nextData?.buildId || 'unknown',
        props: nextData?.props ? 'present' : 'none',
      });
    }

    // Nuxt
    if (window.__NUXT__ || window.$nuxt) {
      frameworks.push({ name: 'Nuxt', version: 'detected' });
    }

    // jQuery
    if (window.jQuery || window.$?.fn?.jquery) {
      frameworks.push({ name: 'jQuery', version: window.jQuery?.fn?.jquery || 'unknown' });
    }

    // Lodash/Underscore
    if (window._ && window._.VERSION) {
      frameworks.push({ name: 'Lodash/Underscore', version: window._.VERSION });
    }

    return frameworks;
  }

  // ============================================================
  // TECHNOLOGY DETECTION (CMS, Server, Cloud, etc.)
  // ============================================================

  function detectTechnologies() {
    const technologies = [];
    const html = document.documentElement.outerHTML;
    const url = location.href;

    // Helper: check if pattern exists in script src or link href (more precise)
    const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
    const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href.toLowerCase());
    const allResources = [...scripts, ...links].join(' ');

    // Helper: check for specific attributes/elements
    const hasElement = (selector) => document.querySelector(selector) !== null;
    const hasScriptSrc = (pattern) => scripts.some(s => s.includes(pattern));
    const hasLinkHref = (pattern) => links.some(l => l.includes(pattern));

    // CMS Detection - very specific patterns
    if (hasScriptSrc('/wp-content/') || hasScriptSrc('/wp-includes/') || hasLinkHref('/wp-content/')) {
      technologies.push({ name: 'WordPress', category: 'cms', evidence: 'wp-content/wp-includes paths' });
    }
    if (hasElement('[data-drupal-selector]') || html.includes('Drupal.settings')) {
      technologies.push({ name: 'Drupal', category: 'cms', evidence: 'Drupal selectors' });
    }
    if (hasScriptSrc('cdn.shopify.com') || url.includes('.myshopify.com')) {
      technologies.push({ name: 'Shopify', category: 'cms', evidence: 'Shopify CDN' });
    }
    if (hasScriptSrc('static.wixstatic.com') || hasScriptSrc('wix.com')) {
      technologies.push({ name: 'Wix', category: 'cms', evidence: 'Wix static' });
    }
    if (hasScriptSrc('squarespace.com') || hasScriptSrc('static.squarespace')) {
      technologies.push({ name: 'Squarespace', category: 'cms', evidence: 'Squarespace CDN' });
    }
    if (hasScriptSrc('ctfassets.net') || hasScriptSrc('contentful.com')) {
      technologies.push({ name: 'Contentful', category: 'cms', evidence: 'Contentful assets' });
    }

    // Framework Detection - check for specific globals or elements
    if (window.__NEXT_DATA__ || hasElement('#__next') || hasScriptSrc('/_next/')) {
      technologies.push({ name: 'Next.js', category: 'framework', evidence: '__NEXT_DATA__ or _next paths' });
    }
    if (window.__NUXT__ || window.$nuxt || hasScriptSrc('/_nuxt/')) {
      technologies.push({ name: 'Nuxt.js', category: 'framework', evidence: '__NUXT__ global' });
    }
    if (hasElement('[data-reactroot]') || hasElement('[data-reactid]') || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      technologies.push({ name: 'React', category: 'framework', evidence: 'React root element' });
    }
    if (window.Vue || hasElement('[data-v-]')) {
      technologies.push({ name: 'Vue.js', category: 'framework', evidence: 'Vue markers' });
    }
    if (window.ng || hasElement('[ng-app]') || hasElement('[ng-controller]') || hasElement('app-root')) {
      technologies.push({ name: 'Angular', category: 'framework', evidence: 'Angular markers' });
    }
    if (hasElement('[data-svelte]') || window.__svelte) {
      technologies.push({ name: 'Svelte', category: 'framework', evidence: 'Svelte markers' });
    }
    if (hasElement('astro-island') || hasElement('[data-astro-cid]')) {
      technologies.push({ name: 'Astro', category: 'framework', evidence: 'Astro islands' });
    }
    if (hasElement('[q\\:container]') || window.qwikloader) {
      technologies.push({ name: 'Qwik', category: 'framework', evidence: 'Qwik container' });
    }
    if (hasElement('input[name="__RequestVerificationToken"]') || hasElement('input[name="__VIEWSTATE"]')) {
      technologies.push({ name: 'ASP.NET', category: 'framework', evidence: 'ViewState/RequestVerification' });
    }
    if (hasElement('input[name="csrfmiddlewaretoken"]')) {
      technologies.push({ name: 'Django', category: 'framework', evidence: 'CSRF middleware token' });
    }
    if (hasElement('meta[name="csrf-token"][content]') && html.includes('rails')) {
      technologies.push({ name: 'Ruby on Rails', category: 'framework', evidence: 'Rails CSRF' });
    }

    // Cloud Provider Detection - URL based only
    const hostname = location.hostname.toLowerCase();
    if (hostname.includes('.vercel.app') || hostname.includes('.vercel.com')) {
      technologies.push({ name: 'Vercel', category: 'cloud', evidence: 'Vercel domain' });
    }
    if (hostname.includes('.netlify.app') || hostname.includes('.netlify.com')) {
      technologies.push({ name: 'Netlify', category: 'cloud', evidence: 'Netlify domain' });
    }
    if (hostname.includes('.pages.dev')) {
      technologies.push({ name: 'Cloudflare Pages', category: 'cloud', evidence: 'pages.dev domain' });
    }
    if (hostname.includes('.herokuapp.com')) {
      technologies.push({ name: 'Heroku', category: 'cloud', evidence: 'Heroku domain' });
    }
    if (hostname.includes('.azurewebsites.net') || hostname.includes('.azurestaticapps.net')) {
      technologies.push({ name: 'Azure', category: 'cloud', evidence: 'Azure domain' });
    }
    if (hostname.includes('.github.io')) {
      technologies.push({ name: 'GitHub Pages', category: 'cloud', evidence: 'github.io domain' });
    }
    if (hostname.includes('.firebaseapp.com') || hostname.includes('.web.app')) {
      technologies.push({ name: 'Firebase', category: 'cloud', evidence: 'Firebase domain' });
    }

    // Analytics Detection - script src only
    if (hasScriptSrc('google-analytics.com') || hasScriptSrc('gtag/js') || hasScriptSrc('/gtag.js')) {
      technologies.push({ name: 'Google Analytics', category: 'analytics', evidence: 'GA script' });
    }
    if (hasScriptSrc('googletagmanager.com/gtm')) {
      technologies.push({ name: 'Google Tag Manager', category: 'analytics', evidence: 'GTM script' });
    }
    if (hasScriptSrc('hotjar.com') || hasScriptSrc('static.hotjar.com')) {
      technologies.push({ name: 'Hotjar', category: 'analytics', evidence: 'Hotjar script' });
    }
    if (hasScriptSrc('cdn.segment.com') || hasScriptSrc('segment.io')) {
      technologies.push({ name: 'Segment', category: 'analytics', evidence: 'Segment script' });
    }
    if (hasScriptSrc('cdn.amplitude.com')) {
      technologies.push({ name: 'Amplitude', category: 'analytics', evidence: 'Amplitude script' });
    }
    if (hasScriptSrc('plausible.io')) {
      technologies.push({ name: 'Plausible', category: 'analytics', evidence: 'Plausible script' });
    }

    // CSS Frameworks - link href or class patterns
    if (hasLinkHref('bootstrap') || hasScriptSrc('bootstrap')) {
      technologies.push({ name: 'Bootstrap', category: 'css', evidence: 'Bootstrap resources' });
    }
    if (html.includes('class="tw-') || html.includes('class="bg-gradient-') || hasScriptSrc('tailwind')) {
      technologies.push({ name: 'Tailwind CSS', category: 'css', evidence: 'Tailwind classes' });
    }

    // Check meta generator tag (most reliable)
    const generatorMeta = document.querySelector('meta[name="generator"]');
    if (generatorMeta) {
      const content = generatorMeta.getAttribute('content') || '';
      if (content && !technologies.find(t => t.name.toLowerCase() === content.split(/\s+/)[0].toLowerCase())) {
        technologies.push({
          name: content.split(/\s+/)[0] || content,
          category: 'cms',
          confidence: 'high',
          evidence: `Generator: ${content}`,
          version: content.match(/[\d.]+/)?.[0] || null,
        });
      }
    }

    return technologies;
  }

  // ============================================================
  // SECURITY HEADERS ANALYSIS
  // ============================================================

  async function analyzeSecurityHeaders() {
    // SCOPE CHECK: Only run on main frame, skip third-party iframes
    if (!isMainFrame || shouldSkipDomain(location.hostname)) {
      return;
    }

    try {
      // Fetch the current page to get response headers
      const response = await fetch(location.href, { method: 'HEAD', credentials: 'same-origin' });
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      // Check CSP
      const csp = headers['content-security-policy'];
      if (!csp) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Content-Security-Policy',
          severity: 'medium',
          description: 'No CSP header - XSS attacks easier to exploit',
          url: location.href,
        });
      } else {
        // Check for weak CSP directives
        if (csp.includes("'unsafe-inline'")) {
          reportFinding('WEAK_CSP', {
            header: 'Content-Security-Policy',
            issue: "unsafe-inline allowed",
            severity: 'medium',
            description: 'CSP allows inline scripts, reducing XSS protection',
            url: location.href,
            value: csp,
          });
        }
        if (csp.includes("'unsafe-eval'")) {
          reportFinding('WEAK_CSP', {
            header: 'Content-Security-Policy',
            issue: "unsafe-eval allowed",
            severity: 'medium',
            description: 'CSP allows eval(), enabling code injection',
            url: location.href,
            value: csp,
          });
        }
        if (csp.includes('*') && !csp.includes('*.')) {
          reportFinding('WEAK_CSP', {
            header: 'Content-Security-Policy',
            issue: "Wildcard source",
            severity: 'high',
            description: 'CSP allows any source with wildcard',
            url: location.href,
            value: csp,
          });
        }
      }

      // Check CORS
      const cors = headers['access-control-allow-origin'];
      if (cors === '*') {
        reportFinding('PERMISSIVE_CORS', {
          header: 'Access-Control-Allow-Origin',
          value: '*',
          severity: 'medium',
          description: 'CORS allows any origin - may leak sensitive data',
          url: location.href,
        });
      }

      // Check X-Frame-Options
      const xfo = headers['x-frame-options'];
      if (!xfo && !csp?.includes('frame-ancestors')) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'X-Frame-Options',
          severity: 'low',
          description: 'No clickjacking protection',
          url: location.href,
        });
      }

      // Check HSTS
      const hsts = headers['strict-transport-security'];
      if (!hsts && location.protocol === 'https:') {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Strict-Transport-Security',
          severity: 'low',
          description: 'No HSTS - vulnerable to SSL stripping',
          url: location.href,
        });
      }

      // Check X-Content-Type-Options
      if (!headers['x-content-type-options']) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'X-Content-Type-Options',
          severity: 'low',
          description: 'Missing nosniff - MIME type sniffing possible',
          url: location.href,
        });
      }

      // Server disclosure
      const server = headers['server'];
      const poweredBy = headers['x-powered-by'];
      if (server && /\d/.test(server)) {
        reportFinding('SERVER_DISCLOSURE', {
          header: 'Server',
          value: server,
          severity: 'info',
          description: 'Server version disclosed',
          url: location.href,
        });
      }
      if (poweredBy) {
        reportFinding('SERVER_DISCLOSURE', {
          header: 'X-Powered-By',
          value: poweredBy,
          severity: 'info',
          description: 'Technology stack disclosed',
          url: location.href,
        });
      }

    } catch (e) {
      // Silent fail - CORS might block this
    }
  }

  // ============================================================
  // ERROR PAGE SERVER FINGERPRINTING
  // ============================================================

  async function fingerprintFromErrorPages() {
    // SCOPE CHECK: Only run on main frame, skip third-party iframes
    if (!isMainFrame || shouldSkipDomain(location.hostname)) {
      return;
    }

    // Request a non-existent path to get error page
    const testUrl = location.origin + '/lonkero-probe-' + Date.now();

    try {
      const response = await fetch(testUrl, {
        method: 'GET',
        credentials: 'omit',
        redirect: 'manual'
      });

      const text = await response.text();

      // Known server signatures in error pages
      const serverPatterns = [
        { pattern: /openresty/i, name: 'OpenResty', type: 'server' },
        { pattern: /nginx/i, name: 'nginx', type: 'server' },
        { pattern: /apache/i, name: 'Apache', type: 'server' },
        { pattern: /Microsoft-IIS/i, name: 'IIS', type: 'server' },
        { pattern: /cloudflare/i, name: 'Cloudflare', type: 'cdn' },
        { pattern: /varnish/i, name: 'Varnish', type: 'cache' },
        { pattern: /LiteSpeed/i, name: 'LiteSpeed', type: 'server' },
        { pattern: /Caddy/i, name: 'Caddy', type: 'server' },
        { pattern: /Tengine/i, name: 'Tengine', type: 'server' },
        { pattern: /AkamaiGHost/i, name: 'Akamai', type: 'cdn' },
        { pattern: /Fastly/i, name: 'Fastly', type: 'cdn' },
        { pattern: /Express/i, name: 'Express.js', type: 'framework' },
        { pattern: /PHP\/[\d.]+/i, name: 'PHP', type: 'runtime' },
        { pattern: /ASP\.NET/i, name: 'ASP.NET', type: 'framework' },
        { pattern: /Tomcat/i, name: 'Tomcat', type: 'server' },
        { pattern: /Jetty/i, name: 'Jetty', type: 'server' },
        { pattern: /WEBrick/i, name: 'WEBrick (Ruby)', type: 'server' },
        { pattern: /Kestrel/i, name: 'Kestrel (.NET)', type: 'server' },
        { pattern: /gunicorn/i, name: 'Gunicorn (Python)', type: 'server' },
        { pattern: /uvicorn/i, name: 'Uvicorn (Python)', type: 'server' },
        { pattern: /werkzeug/i, name: 'Werkzeug (Flask)', type: 'framework' },
        { pattern: /Phusion Passenger/i, name: 'Passenger', type: 'server' },
      ];

      for (const { pattern, name, type } of serverPatterns) {
        if (pattern.test(text)) {
          // Extract version if present
          const versionMatch = text.match(new RegExp(name + '[/\\s]*([\\d.]+)', 'i'));
          const version = versionMatch ? versionMatch[1] : null;

          reportFinding('SERVER_DISCLOSURE', {
            source: 'error_page',
            server: name,
            version: version,
            type: type,
            status: response.status,
            severity: 'info',
            description: `${name}${version ? ' ' + version : ''} detected from error page`,
            url: location.href,
          });
          break; // Only report the first/main server found
        }
      }

    } catch (e) {
      // Network error - ignore
    }
  }

  // ============================================================
  // COOKIE SECURITY AUDIT
  // ============================================================

  function auditCookies() {
    const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);

    for (const cookie of cookies) {
      const [name] = cookie.split('=');
      if (!name) continue;

      // Check for sensitive cookie names without HttpOnly (we can read them = not HttpOnly)
      const sensitivePatterns = [
        /session/i, /token/i, /auth/i, /jwt/i, /api.?key/i,
        /csrf/i, /xsrf/i, /login/i, /user/i, /admin/i
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(name)) {
          reportFinding('INSECURE_COOKIE', {
            cookie: name,
            issue: 'Accessible via JavaScript (no HttpOnly)',
            severity: 'medium',
            description: `Sensitive cookie "${name}" readable by JS - vulnerable to XSS theft`,
            url: location.href,
          });
          break;
        }
      }
    }

    // Check for cookies on HTTP
    if (location.protocol === 'http:' && cookies.length > 0) {
      reportFinding('INSECURE_COOKIE', {
        issue: 'Cookies over HTTP',
        severity: 'high',
        description: 'Cookies transmitted over unencrypted HTTP',
        url: location.href,
        cookieCount: cookies.length,
      });
    }
  }

  // ============================================================
  // OPEN REDIRECT DETECTION
  // ============================================================

  function checkOpenRedirect() {
    const params = new URLSearchParams(location.search);
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo',
                           'goto', 'target', 'destination', 'redir', 'redirect_uri',
                           'continue', 'callback', 'forward', 'out', 'link'];

    for (const param of redirectParams) {
      const value = params.get(param);
      if (value) {
        // Check if it looks like a URL
        if (value.startsWith('http') || value.startsWith('//') || value.startsWith('/')) {
          reportFinding('OPEN_REDIRECT_PARAM', {
            parameter: param,
            value: value,
            severity: 'medium',
            description: `URL in "${param}" parameter - potential open redirect`,
            url: location.href,
          });
        }
      }
    }

    // Also check hash
    const hash = location.hash;
    if (hash && (hash.includes('http') || hash.includes('//'))) {
      reportFinding('OPEN_REDIRECT_PARAM', {
        source: 'hash',
        value: hash,
        severity: 'low',
        description: 'URL in hash fragment - potential DOM-based redirect',
        url: location.href,
      });
    }
  }

  // ============================================================
  // JWT DECODER & ANALYSIS
  // ============================================================

  function analyzeJWTs() {
    // Check localStorage
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      if (value && isJWT(value)) {
        analyzeJWT(value, `localStorage[${key}]`);
      }
    }

    // Check sessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);
      if (value && isJWT(value)) {
        analyzeJWT(value, `sessionStorage[${key}]`);
      }
    }

    // Check cookies
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.split('=');
      const value = valueParts.join('=').trim();
      if (value && isJWT(value)) {
        analyzeJWT(value, `cookie[${name.trim()}]`);
      }
    }
  }

  function isJWT(str) {
    if (!str || typeof str !== 'string') return false;
    const parts = str.split('.');
    if (parts.length !== 3) return false;
    try {
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      return header.alg && header.typ === 'JWT';
    } catch {
      return false;
    }
  }

  function analyzeJWT(jwt, source) {
    try {
      const [headerB64, payloadB64] = jwt.split('.');
      const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));

      // Check for weak algorithms
      if (header.alg === 'none' || header.alg === 'None') {
        reportFinding('JWT_VULNERABILITY', {
          source: source,
          issue: 'Algorithm none',
          severity: 'critical',
          description: 'JWT uses "none" algorithm - signature not verified',
          header: header,
          url: location.href,
        });
      }

      if (header.alg === 'HS256' && payload.iss) {
        reportFinding('JWT_INFO', {
          source: source,
          algorithm: header.alg,
          issuer: payload.iss,
          severity: 'info',
          description: 'JWT found - HS256 may be vulnerable to secret brute-force',
          url: location.href,
        });
      }

      // Check expiration
      if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        const now = new Date();
        if (expDate < now) {
          reportFinding('JWT_EXPIRED', {
            source: source,
            expiredAt: expDate.toISOString(),
            severity: 'low',
            description: 'Expired JWT still present',
            url: location.href,
          });
        }
      } else {
        reportFinding('JWT_NO_EXPIRY', {
          source: source,
          severity: 'medium',
          description: 'JWT has no expiration - tokens valid forever',
          url: location.href,
        });
      }

      // Check for sensitive data in payload
      const sensitiveKeys = ['password', 'secret', 'apikey', 'api_key', 'private', 'ssn', 'credit'];
      for (const key of Object.keys(payload)) {
        if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
          reportFinding('JWT_SENSITIVE_DATA', {
            source: source,
            field: key,
            severity: 'high',
            description: `JWT contains potentially sensitive field: ${key}`,
            url: location.href,
          });
        }
      }

    } catch (e) {
      // Invalid JWT
    }
  }

  // ============================================================
  // SOURCE MAP DETECTION
  // ============================================================

  // Third-party domains to skip for source map detection (not security issues)
  const thirdPartyDomains = [
    'googletagmanager.com', 'google-analytics.com', 'gtag', 'googlesyndication.com',
    'facebook.net', 'facebook.com', 'fbcdn.net',
    'twitter.com', 'twimg.com',
    'cloudflare.com', 'cdnjs.cloudflare.com', 'cloudfront.net',
    'jsdelivr.net', 'unpkg.com', 'esm.sh',
    'hotjar.com', 'segment.com', 'segment.io', 'mixpanel.com',
    'intercom.io', 'crisp.chat', 'zendesk.com', 'zopim.com',
    'stripe.com', 'js.stripe.com',
    'cdn.shopify.com', 'shopifycdn.com',
    'sentry.io', 'sentry-cdn.com',
    'polyfill.io', 'cdn.polyfill.io',
    'recaptcha.net', 'gstatic.com',
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'maps.googleapis.com', 'maps.gstatic.com',
    'youtube.com', 'ytimg.com',
    'vimeo.com', 'player.vimeo.com',
    'typekit.net', 'use.typekit.net',
    'bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
    'jquery.com', 'code.jquery.com',
    // Consent/Privacy CDNs
    'privacy-mgmt.com', 'sourcepoint.com', 'sp-prod.net',
    'userreport.com', 'ebxcdn.com',
    'onetrust.com', 'cookielaw.org', 'cookiepro.com',
    'consentmanager.net', 'usercentrics.com',
    // Ad networks
    'adnxs.com', 'doubleclick.net', 'pubmatic.com', 'rubiconproject.com',
    'openx.net', 'criteo.com', 'taboola.com', 'outbrain.com',
    // Analytics
    'crazyegg.com', 'mouseflow.com', 'luckyorange.com', 'fullstory.com',
    'logrocket.com', 'heapanalytics.com', 'amplitude.com',
    // General CDNs
    'akamaized.net', 'fastly.net', 'azureedge.net',
  ];

  function isThirdPartyScript(url) {
    try {
      const scriptHost = new URL(url).hostname.toLowerCase();
      const pageHost = location.hostname.toLowerCase();

      // Same origin = not third-party
      if (scriptHost === pageHost) return false;

      // Check global skip list first
      if (shouldSkipDomain(scriptHost)) return true;

      // Check if it's a known third-party service
      for (const domain of thirdPartyDomains) {
        if (scriptHost.includes(domain)) return true;
      }

      // Different domain but not in known list - might be target's CDN
      // Only flag if it's clearly a different organization
      return false;
    } catch {
      return true; // Can't parse URL, skip it
    }
  }

  async function detectSourceMaps() {
    // SCOPE CHECK: Only run on main frame, skip third-party iframes
    if (!isMainFrame || shouldSkipDomain(location.hostname)) {
      return;
    }

    const scripts = document.querySelectorAll('script[src]');

    for (const script of scripts) {
      const src = script.src;
      if (!src || src.includes('chrome-extension://')) continue;

      // Skip third-party scripts (not a security issue for the target)
      if (isThirdPartyScript(src)) continue;

      // Check if .map file exists
      const mapUrl = src + '.map';
      try {
        const response = await fetch(mapUrl, { method: 'HEAD' });
        if (response.ok) {
          reportFinding('SOURCE_MAP_EXPOSED', {
            script: src,
            mapUrl: mapUrl,
            severity: 'low',
            description: 'Source map file accessible - may reveal source code',
            url: location.href,
          });
        }
      } catch {
        // Network error or CORS - ignore
      }
    }

    // Check CSS source maps too (only same-origin)
    const styles = document.querySelectorAll('link[rel="stylesheet"]');
    for (const style of styles) {
      const href = style.href;
      if (!href || href.includes('chrome-extension://')) continue;

      // Skip third-party stylesheets
      if (isThirdPartyScript(href)) continue;

      const mapUrl = href + '.map';
      try {
        const response = await fetch(mapUrl, { method: 'HEAD' });
        if (response.ok) {
          reportFinding('SOURCE_MAP_EXPOSED', {
            stylesheet: href,
            mapUrl: mapUrl,
            severity: 'info',
            description: 'CSS source map accessible',
            url: location.href,
          });
        }
      } catch {
        // Ignore
      }
    }
  }

  // ============================================================
  // SENSITIVE PATHS CHECK (with content validation)
  // ============================================================

  // Content validators - patterns that MUST be present for a valid finding
  const pathValidators = {
    '/.git/config': /\[core\]|\[remote|\[branch/i,
    '/.env': /^[A-Z_]+=|DB_|API_KEY|SECRET|PASSWORD/im,
    '/.env.local': /^[A-Z_]+=|DB_|API_KEY|SECRET|PASSWORD/im,
    '/wp-config.php': /DB_NAME|DB_USER|DB_PASSWORD|WP_DEBUG|\<\?php/i,
    '/config.php': /\<\?php|define\(|password|database/i,
    '/phpinfo.php': /phpinfo\(\)|PHP Version|php\.ini/i,
    '/server-status': /Apache Server Status|Server uptime|requests\/sec/i,
    '/elmah.axd': /ELMAH|Error Log|Exception/i,
    '/trace.axd': /ASP\.NET Trace|Request Details|Trace Information/i,
    '/.htaccess': /RewriteRule|RewriteCond|AuthType|Require/i,
    '/web.config': /\<configuration|\<system\.web|\<appSettings/i,
    '/crossdomain.xml': /\<cross-domain-policy|\<allow-access-from/i,
    '/clientaccesspolicy.xml': /\<access-policy|\<cross-domain-access/i,
    '/.well-known/security.txt': /Contact:|Expires:|Policy:/i,
    '/robots.txt': /User-agent:|Disallow:|Allow:|Sitemap:/i,
    '/sitemap.xml': /\<urlset|\<sitemapindex|\<url\>/i,
    '/graphql': /"data"|"errors"|__schema|__typename/i,
    '/swagger.json': /"swagger"|"openapi"|"paths"|"info"/i,
    '/api-docs': /"swagger"|"openapi"|Swagger UI|API Documentation/i,
    '/api/swagger': /"swagger"|"openapi"|Swagger UI|API Documentation/i,
  };

  // Patterns that indicate a soft 404 (SPA returning 200 but showing error)
  const soft404Patterns = [
    /404|not found|page not found|sivua ei löydy|sidan hittades inte/i,
    /page doesn't exist|does not exist|couldn't find/i,
    /no such page|invalid page|error 404/i,
    /<title>[^<]*404[^<]*<\/title>/i,
    /<h1>[^<]*not found[^<]*<\/h1>/i,
  ];

  async function checkSensitivePaths() {
    // SCOPE CHECK: Only run on main frame, skip third-party iframes
    if (!isMainFrame) {
      console.log('[Lonkero] Skipping sensitive path check - not main frame');
      return;
    }

    // Skip third-party domains entirely
    if (shouldSkipDomain(location.hostname)) {
      console.log('[Lonkero] Skipping sensitive path check - third-party domain:', location.hostname);
      return;
    }

    const sensitivePaths = [
      { path: '/.git/config', name: 'Git config', severity: 'critical' },
      { path: '/.env', name: 'Environment file', severity: 'critical' },
      { path: '/.env.local', name: 'Local env file', severity: 'critical' },
      { path: '/wp-config.php', name: 'WordPress config', severity: 'critical' },
      { path: '/config.php', name: 'PHP config', severity: 'high' },
      { path: '/phpinfo.php', name: 'PHP info', severity: 'medium' },
      { path: '/server-status', name: 'Apache status', severity: 'medium' },
      { path: '/elmah.axd', name: 'ELMAH error log', severity: 'high' },
      { path: '/trace.axd', name: 'ASP.NET trace', severity: 'high' },
      { path: '/.htaccess', name: 'Apache htaccess', severity: 'medium' },
      { path: '/web.config', name: 'IIS config', severity: 'high' },
      { path: '/crossdomain.xml', name: 'Flash crossdomain', severity: 'low' },
      { path: '/clientaccesspolicy.xml', name: 'Silverlight policy', severity: 'low' },
      { path: '/.well-known/security.txt', name: 'Security.txt', severity: 'info' },
      { path: '/robots.txt', name: 'Robots.txt', severity: 'info' },
      { path: '/sitemap.xml', name: 'Sitemap', severity: 'info' },
      { path: '/graphql', name: 'GraphQL endpoint', severity: 'info' },
      { path: '/api/swagger', name: 'Swagger docs', severity: 'info' },
      { path: '/swagger.json', name: 'Swagger JSON', severity: 'info' },
      { path: '/api-docs', name: 'API docs', severity: 'info' },
    ];

    const origin = location.origin;
    const checked = new Set();

    for (const { path, name, severity } of sensitivePaths) {
      const fullUrl = origin + path;
      if (checked.has(fullUrl)) continue;
      checked.add(fullUrl);

      try {
        // Use GET to read the body (not HEAD)
        const response = await fetch(fullUrl, {
          method: 'GET',
          credentials: 'omit',
          redirect: 'manual'
        });

        // Skip non-200 responses
        if (response.status !== 200) continue;

        const text = await response.text();

        // Skip if it's a soft 404 (SPA showing "not found" with 200 status)
        if (soft404Patterns.some(p => p.test(text))) {
          continue;
        }

        // Validate content matches what we expect for this file type
        const validator = pathValidators[path];
        if (validator && !validator.test(text)) {
          // Content doesn't match expected pattern - likely a SPA catch-all
          continue;
        }

        // Content validated - this is a real finding
        const evidence = text.substring(0, 200).replace(/\s+/g, ' ').trim();
        reportFinding('SENSITIVE_PATH', {
          path: path,
          name: name,
          status: response.status,
          severity: severity,
          description: `${name} accessible at ${path}`,
          url: fullUrl,
          evidence: evidence.length > 100 ? evidence.substring(0, 100) + '...' : evidence,
        });

      } catch {
        // Network error - ignore
      }
    }
  }

  // ============================================================
  // MIXED CONTENT DETECTION
  // ============================================================

  function detectMixedContent() {
    if (location.protocol !== 'https:') return;

    // Check scripts
    document.querySelectorAll('script[src^="http:"]').forEach(script => {
      reportFinding('MIXED_CONTENT', {
        type: 'script',
        resource: script.src,
        severity: 'high',
        description: 'HTTP script loaded on HTTPS page - can be MITM attacked',
        url: location.href,
      });
    });

    // Check stylesheets
    document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach(link => {
      reportFinding('MIXED_CONTENT', {
        type: 'stylesheet',
        resource: link.href,
        severity: 'medium',
        description: 'HTTP stylesheet on HTTPS page',
        url: location.href,
      });
    });

    // Check images
    document.querySelectorAll('img[src^="http:"]').forEach(img => {
      reportFinding('MIXED_CONTENT', {
        type: 'image',
        resource: img.src,
        severity: 'low',
        description: 'HTTP image on HTTPS page',
        url: location.href,
      });
    });

    // Check iframes
    document.querySelectorAll('iframe[src^="http:"]').forEach(iframe => {
      reportFinding('MIXED_CONTENT', {
        type: 'iframe',
        resource: iframe.src,
        severity: 'high',
        description: 'HTTP iframe on HTTPS page - content can be modified',
        url: location.href,
      });
    });

    // Check forms posting to HTTP
    document.querySelectorAll('form[action^="http:"]').forEach(form => {
      reportFinding('MIXED_CONTENT', {
        type: 'form',
        resource: form.action,
        severity: 'critical',
        description: 'Form submits to HTTP - credentials exposed',
        url: location.href,
      });
    });
  }

  // ============================================================
  // CLOUD STORAGE & GRAPHQL DISCOVERY
  // ============================================================

  const discoveredCloudStorage = new Set();
  const discoveredGraphQL = new Set();

  // Scan content for cloud storage buckets
  function scanForCloudStorage(content, source) {
    // S3 buckets
    const s3Patterns = [
      /https?:\/\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3[\.-]([a-z0-9\-]+)\.amazonaws\.com/gi,
      /https?:\/\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/gi,
      /https?:\/\/s3[\.-]([a-z0-9\-]+)\.amazonaws\.com\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi,
    ];

    // Azure Blob Storage
    const azurePattern = /https?:\/\/([a-z0-9]+)\.blob\.core\.windows\.net/gi;

    // Google Cloud Storage
    const gcsPatterns = [
      /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9_\-\.]{1,61}[a-z0-9])/gi,
      /https?:\/\/storage\.cloud\.google\.com\/([a-z0-9][a-z0-9_\-\.]{1,61}[a-z0-9])/gi,
    ];

    for (const pattern of s3Patterns) {
      for (const match of content.matchAll(pattern)) {
        const url = match[0];
        if (!discoveredCloudStorage.has(url)) {
          discoveredCloudStorage.add(url);
          reportFinding('CLOUD_STORAGE', {
            type: 'S3',
            url: url,
            source: source,
          });
        }
      }
    }

    for (const match of content.matchAll(azurePattern)) {
      const url = match[0];
      if (!discoveredCloudStorage.has(url)) {
        discoveredCloudStorage.add(url);
        reportFinding('CLOUD_STORAGE', {
          type: 'Azure Blob',
          url: url,
          source: source,
        });
      }
    }

    for (const pattern of gcsPatterns) {
      for (const match of content.matchAll(pattern)) {
        const url = match[0];
        if (!discoveredCloudStorage.has(url)) {
          discoveredCloudStorage.add(url);
          reportFinding('CLOUD_STORAGE', {
            type: 'GCS',
            url: url,
            source: source,
          });
        }
      }
    }
  }

  // Scan content for GraphQL endpoints
  function scanForGraphQL(content, source) {
    const graphqlPatterns = [
      /["'`](https?:\/\/[^"'`\s]+\/graphql[^"'`\s]*)/gi,
      /["'`](\/graphql[^"'`\s]*)/gi,
      /["'`](\/api\/graphql[^"'`\s]*)/gi,
      /uri\s*[:=]\s*["'`]([^"'`]+graphql[^"'`]*)/gi,
      /endpoint\s*[:=]\s*["'`]([^"'`]+graphql[^"'`]*)/gi,
      /GRAPHQL_ENDPOINT\s*[:=]\s*["'`]([^"'`]+)/gi,
    ];

    for (const pattern of graphqlPatterns) {
      for (const match of content.matchAll(pattern)) {
        const endpoint = match[1];
        if (!discoveredGraphQL.has(endpoint) && !isThirdParty(endpoint)) {
          discoveredGraphQL.add(endpoint);
          safeSendMessage({
            type: 'endpointDiscovered',
            endpoint: {
              method: 'POST',
              url: endpoint.startsWith('/') ? location.origin + endpoint : endpoint,
              path: endpoint,
              isApi: true,
              isGraphQL: true,
              source: source,
              origin: location.href,
            }
          });
        }
      }
    }
  }

  // ============================================================
  // REPORTING
  // ============================================================

  // Store findings locally in case extension context is invalidated
  let pendingFindings = [];

  function reportFinding(type, data) {
    // License gate: don't forward findings from unlicensed sessions.
    // Even if scanner files produce findings, this layer blocks them.
    if (!__lonkeroLicensed) return;

    const finding = {
      type: type,
      timestamp: new Date().toISOString(),
      ...data,
    };

    findings.push(finding);

    // Send to background script with error handling
    try {
      // Check if chrome.runtime is still valid
      if (!chrome.runtime?.id) {
        console.warn('[Lonkero] Extension context invalidated, storing finding locally');
        pendingFindings.push(finding);
        return;
      }

      chrome.runtime.sendMessage({
        type: 'finding',
        finding: finding,
      }).catch(e => {
        // Extension context invalidated or other error
        console.warn('[Lonkero] Failed to send finding, storing locally:', e.message);
        pendingFindings.push(finding);
      });
    } catch (e) {
      // Synchronous error (context already invalid)
      console.warn('[Lonkero] Extension context error, storing finding locally:', e.message);
      pendingFindings.push(finding);
    }

    console.log('[Lonkero] Finding:', type, data);
    _t('content_finding', { type });
  }

  // Retry sending pending findings periodically
  setInterval(() => {
    if (pendingFindings.length > 0 && chrome.runtime?.id) {
      const toSend = [...pendingFindings];
      pendingFindings = [];
      for (const finding of toSend) {
        try {
          chrome.runtime.sendMessage({ type: 'finding', finding }).catch(() => {
            pendingFindings.push(finding);
          });
        } catch {
          pendingFindings.push(finding);
        }
      }
    }
  }, 5000);

  // ============================================================
  // INITIALIZATION
  // ============================================================

  function init() {
    // PASSIVE detections only - no active probing to avoid WAF bans
    // Active scans (source maps, sensitive paths, security headers) are now MANUAL via popup buttons
    setTimeout(() => {
      // These are safe passive checks - no network requests
      checkSources();
      checkPrototypePollution();

      // Delayed passive scans
      setTimeout(() => {
        // Scan inline scripts for secrets (no network requests)
        scanInlineScripts();

        const sessionData = extractSessionData();
        const frameworks = detectFrameworks();
        const technologies = detectTechnologies();

        // Report page analysis (passive only)
        safeSendMessage({
          type: 'pageAnalysis',
          data: {
            url: location.href,
            title: document.title,
            frameworks: frameworks,
            technologies: technologies,
            endpoints: Array.from(discoveredEndpoints),
            graphqlEndpoints: Array.from(discoveredGraphQL),
            cloudStorage: Array.from(discoveredCloudStorage),
            sessionData: sessionData,
            findingsCount: findings.length,
          }
        });

        // NOTE: These active scans are now DISABLED by default to avoid WAF detection
        // They can be triggered manually via popup buttons:
        // - analyzeSecurityHeaders()  -> "Headers Scan" button
        // - detectSourceMaps()        -> "Source Maps" button
        // - checkSensitivePaths()     -> "Sensitive Paths" button
        // - scanExternalScripts()     -> "Secrets Scan" button
        // - detectMixedContent()      -> Part of "Full Scan"
        // - checkOpenRedirect()       -> Part of "Full Scan"
        // - auditCookies()            -> Part of "Full Scan"
        // - analyzeJWTs()             -> Part of "Full Scan"
      }, 1000);
    }, 500);

    // Periodic passive checks only
    setInterval(checkPrototypePollution, 5000);
  }

  // ============================================================
  // MANUAL SCAN FUNCTIONS (triggered from popup)
  // ============================================================

  // Run all active scans
  async function runFullScan() {
    console.log('[Lonkero] Running full scan...');
    const results = { findings: 0, errors: [] };

    try {
      // Security headers
      await analyzeSecurityHeaders();

      // Source maps
      await detectSourceMaps();

      // Sensitive paths
      await checkSensitivePaths();

      // External scripts for secrets
      scanExternalScripts();

      // Other checks
      detectMixedContent();
      checkOpenRedirect();
      auditCookies();
      analyzeJWTs();

      results.findings = findings.length;
      console.log('[Lonkero] Full scan complete:', results);
    } catch (e) {
      results.errors.push(e.message);
      console.error('[Lonkero] Full scan error:', e);
    }

    return results;
  }

  // Individual scan functions for granular control
  async function runHeadersScan() {
    console.log('[Lonkero] Running security headers scan...');
    await analyzeSecurityHeaders();
    return { success: true };
  }

  async function runSourceMapsScan() {
    console.log('[Lonkero] Running source maps scan...');
    await detectSourceMaps();
    return { success: true };
  }

  async function runSensitivePathsScan() {
    console.log('[Lonkero] Running sensitive paths scan...');
    await checkSensitivePaths();
    return { success: true };
  }

  async function runSecretsScan() {
    console.log('[Lonkero] Running secrets scan...');
    scanInlineScripts();
    scanExternalScripts();
    return { success: true };
  }

  // Scan functions are called internally — no need to expose on window

  // Inject Form Fuzzer into page context
  function injectFormFuzzer() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('formfuzzer.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
      console.log('[Lonkero] Form Fuzzer injected');
    } catch (e) {
      console.warn('[Lonkero] Failed to inject Form Fuzzer:', e);
    }
  }

  // Inject GraphQL Fuzzer into page context
  function injectGraphQLFuzzer() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('graphql-fuzzer.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
      console.log('[Lonkero] GraphQL Fuzzer injected');
    } catch (e) {
      console.warn('[Lonkero] Failed to inject GraphQL Fuzzer:', e);
    }
  }

  // Inject Merlin (vulnerable library scanner) into page context
  function injectMerlin() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('merlin.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
      console.log('[Lonkero] Merlin (vulnerable library scanner) injected');
    } catch (e) {
      console.warn('[Lonkero] Failed to inject Merlin:', e);
    }
  }

  // Inject XSS Scanner into page context
  function injectXSSScanner() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('xss-scanner.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
      console.log('[Lonkero] XSS Scanner injected');
    } catch (e) {
      console.warn('[Lonkero] Failed to inject XSS Scanner:', e);
    }
  }

  // Inject CMS Scanner into page context
  function injectCMSScanner() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('cms-scanner.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
      console.log('[Lonkero] CMS Scanner injected');
    } catch (e) {
      console.warn('[Lonkero] Failed to inject CMS Scanner:', e);
    }
  }

  // Inject request interceptors into page context (main world)
  function injectRequestInterceptors() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('interceptors.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      console.warn('[Lonkero] Failed to inject request interceptors:', e);
    }
  }

  // Listen for messages from injected script
  window.addEventListener('message', function(event) {
    if (event.source !== window) return;

    // Only accept messages on our per-session channel
    const msgCh = event.data?._ch;
    if (!msgCh || msgCh !== __evtChannel) return;

    // License gate: don't forward any scanner data from unlicensed sessions.
    if (!__lonkeroLicensed) return;

    // Nonce validation: scanner messages must include the session nonce
    if (__msgNonce && event.data._n !== __msgNonce) return;

    if (event.data?.type === '__lonkero_request__') {
      const req = event.data.request;
      // Send to background for capture
      safeSendMessage({
        type: 'requestCaptured',
        request: req
      });
      // Also discover endpoint
      discoverEndpoint(req.url, req.method, 'page');
    }

    // Handle Merlin vulnerability findings
    if (event.data?.type === '__lonkero_merlin_finding__') {
      const finding = event.data.finding;
      reportFinding('VULNERABLE_LIBRARY', {
        library: finding.library,
        version: finding.version,
        cves: finding.cves,
        severity: finding.severity,
        description: finding.description,
        url: location.href,
      });
    }

    // Handle Merlin scan complete
    if (event.data?.type === '__lonkero_merlin_scan_complete__') {
      safeSendMessage({
        type: 'merlinScanComplete',
        libraries: event.data.libraries,
        vulnCount: event.data.vulnCount,
      });
    }

    // Handle XSS findings
    if (event.data?.type === '__lonkero_xss_finding__') {
      const finding = event.data.finding;
      reportFinding(finding.type, {
        parameter: finding.parameter,
        context: finding.context,
        severity: finding.severity,
        url: finding.url,
        proof: finding.proof,
        source: finding.source,
        value: finding.value,
      });
    }

    // Handle XSS scan complete
    if (event.data?.type === '__lonkero_xss_scan_complete__') {
      safeSendMessage({
        type: 'xssScanComplete',
        findings: event.data.findings,
        tested: event.data.tested,
      });
    }

    // Handle generic findings from injected scripts (formfuzzer, graphql-fuzzer, etc.)
    if (event.data?.type === '__lonkero_finding__') {
      console.log('[Lonkero Content] Received __lonkero_finding__:', event.data);
      const finding = event.data.finding;
      if (finding && finding.type) {
        console.log('[Lonkero Content] Calling reportFinding for:', finding.type);
        reportFinding(finding.type, {
          ...finding,
          url: finding.url || location.href,
        });
      }
    }

    // Handle framework scanner findings
    if (event.data?.type === '__lonkero_framework_finding__') {
      console.log('[Lonkero Content] Received framework finding:', event.data);
      const finding = event.data.finding;
      if (finding && finding.type) {
        console.log('[Lonkero Content] Calling reportFinding for framework:', finding.type);
        reportFinding(finding.type, {
          ...finding,
          url: finding.url || location.href,
          scanner: 'framework-scanner',
        });
      }
    }

    // Bridge for page scripts to get endpoints from background
    if (event.data?.type === '__lonkero_get_endpoints__') {
      const requestId = event.data.requestId;
      safeSendMessage({ type: 'getEndpoints' }, (endpoints) => {
        // Also include locally discovered GraphQL endpoints
        const graphqlEndpoints = Array.from(discoveredGraphQL).map(url => ({
          method: 'POST',
          url: url.startsWith('/') ? location.origin + url : url,
          path: url,
          isGraphQL: true,
          source: 'js-scan',
          origin: location.href,
        }));

        const allEndpoints = [...(endpoints || []), ...graphqlEndpoints];

        window.postMessage({
          type: '__lonkero_endpoints_response__',
          requestId: requestId,
          endpoints: allEndpoints,
          _n: __msgNonce,
        }, '*');
      });
    }
  });

  // License-gated initialization
  // All scanning features require a valid paid license.
  // The license check goes through the background service worker which
  // validates against the Bountyy license server.
  async function startWithLicenseCheck() {
    __lonkeroLicensed = await checkContentLicense();

    if (!__lonkeroLicensed) {
      console.log('[Lonkero] Extension not licensed. Scanning features disabled.');
      console.log('[Lonkero] Enter your license key in the extension popup to activate.');
      _t('content_unlicensed');
      return;
    }

    // Licensed - inject key and initialize all scanning features
    _t('content_init', { host: location.hostname });
    injectLicenseKey();

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        injectRequestInterceptors();
        init();
        injectFormFuzzer();
        injectGraphQLFuzzer();
        injectMerlin();
        injectXSSScanner();
        injectCMSScanner();
      });
    } else {
      injectRequestInterceptors();
      init();
      injectFormFuzzer();
      injectGraphQLFuzzer();
      injectMerlin();
      injectXSSScanner();
      injectCMSScanner();
    }

    // Re-inject on SPA navigation (for Next.js, React Router, etc.)
    let lastUrl = location.href;
    new MutationObserver(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        _t('spa_navigation', { host: location.hostname });
        // Re-run detection on navigation
        setTimeout(() => {
          checkSources();
          checkPrototypePollution();
          // Re-inject form fuzzer if it's gone
          if (!window.formFuzzer) {
            injectFormFuzzer();
          }
        }, 500);
      }
    }).observe(document, { subtree: true, childList: true });
  }

  startWithLicenseCheck();

})();
