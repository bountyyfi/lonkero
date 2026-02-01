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
  if (window.__lonkeroInjected) return;
  window.__lonkeroInjected = true;

  const findings = [];
  const discoveredEndpoints = new Set();
  const discoveredSecrets = [];

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

    // GitHub - specific prefixes (gh followed by specific letter)
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g },

    // Stripe - specific prefixes
    { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g },
    { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24,}/g },

    // Mapbox
    { name: 'Mapbox Token', pattern: /pk\.eyJ[a-zA-Z0-9_-]{50,}/g },
    { name: 'Mapbox Secret', pattern: /sk\.eyJ[a-zA-Z0-9_-]{50,}/g },

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
    for (const { name, pattern } of SECRET_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          // Avoid duplicates
          const key = `${name}:${match.substring(0, 20)}`;
          if (!discoveredSecrets.includes(key)) {
            discoveredSecrets.push(key);
            reportFinding('SECRET_EXPOSED', {
              type: name,
              value: match.length > 50 ? match.substring(0, 50) + '...' : match,
              source: source,
              url: location.href,
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

        chrome.runtime.sendMessage({
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
          chrome.runtime.sendMessage({
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

  function reportFinding(type, data) {
    const finding = {
      type: type,
      timestamp: new Date().toISOString(),
      ...data,
    };

    findings.push(finding);

    // Send to background script
    chrome.runtime.sendMessage({
      type: 'finding',
      finding: finding,
    });

    console.log('[Lonkero] Finding:', type, data);
  }

  // ============================================================
  // INITIALIZATION
  // ============================================================

  function init() {
    // Run detections
    setTimeout(() => {
      checkSources();
      checkPrototypePollution();
      scanInlineScripts();

      // Delayed scans
      setTimeout(() => {
        scanExternalScripts();

        const sessionData = extractSessionData();
        const frameworks = detectFrameworks();

        // Report page analysis
        chrome.runtime.sendMessage({
          type: 'pageAnalysis',
          data: {
            url: location.href,
            title: document.title,
            frameworks: frameworks,
            endpoints: Array.from(discoveredEndpoints),
            graphqlEndpoints: Array.from(discoveredGraphQL),
            cloudStorage: Array.from(discoveredCloudStorage),
            sessionData: sessionData,
            findingsCount: findings.length,
          }
        });
      }, 1000);
    }, 500);

    // Periodic checks
    setInterval(checkPrototypePollution, 5000);
  }

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

    if (event.data?.type === '__lonkero_request__') {
      const req = event.data.request;
      // Send to background for capture
      chrome.runtime.sendMessage({
        type: 'requestCaptured',
        request: req
      }).catch(() => {});
      // Also discover endpoint
      discoverEndpoint(req.url, req.method, 'page');
    }

    // Bridge for page scripts to get endpoints from background
    if (event.data?.type === '__lonkero_get_endpoints__') {
      const requestId = event.data.requestId;
      chrome.runtime.sendMessage({ type: 'getEndpoints' }, (endpoints) => {
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
        }, '*');
      });
    }
  });

  // Wait for DOM
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      injectRequestInterceptors();
      init();
      injectFormFuzzer();
      injectGraphQLFuzzer();
    });
  } else {
    injectRequestInterceptors();
    init();
    injectFormFuzzer();
    injectGraphQLFuzzer();
  }

  // Re-inject on SPA navigation (for Next.js, React Router, etc.)
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
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

})();
