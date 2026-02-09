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

      // Remove the element after scanners have read it (reduce exposure window)
      setTimeout(() => { try { el.remove(); } catch {} }, 2000);
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

  // DOM XSS sink monitoring moved to dom-hooks.js (MAIN world)
  // to actually intercept page-side calls to innerHTML, document.write, eval

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

    // Basic Auth - base64 encoded credentials (user:pass)
    { name: 'Basic Auth Header', pattern: /[Aa]uthorization["'\s:=]+["']?Basic\s+[A-Za-z0-9+/=]{8,}/g },
    // btoa() with credential-like content
    { name: 'Base64 Credentials', pattern: /btoa\(["'`][^"'`]*:[^"'`]*["'`]\)/g },
    // Hardcoded base64 strings assigned to auth/token/key variables
    { name: 'Base64 Auth Token', pattern: /(?:auth|token|key|credential|password|secret|apiKey)["'\s:=]+["']?[A-Za-z0-9+/]{40,}={0,2}["']?/gi },
    // X-API-Key and custom auth headers
    { name: 'X-API-Key Header', pattern: /[Xx]-[Aa][Pp][Ii]-[Kk]ey["'\s:=]+["']?[a-zA-Z0-9_.-]{16,}/g },
    { name: 'Custom Auth Header', pattern: /[Xx]-[Aa]uth[-_][Tt]oken["'\s:=]+["']?[a-zA-Z0-9_.-]{16,}/g },

    // Google - specific prefixes
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
    // Note: Google OAuth client IDs are PUBLIC (not secrets) - only flag client secrets
    { name: 'Google OAuth Secret', pattern: /(?:client_secret|clientSecret)["'\s:=]+["']?([a-zA-Z0-9_-]{24})/gi },

    // reCAPTCHA
    { name: 'reCAPTCHA Secret', pattern: /(?:secret|secretKey|recaptcha.*secret)["'\s:=]+["']?(6L[a-zA-Z0-9_-]{38})/gi },
    { name: 'reCAPTCHA Site Key', pattern: /(?:data-sitekey|sitekey|site_key|render|reCAPTCHA_site_key|recaptchaKey)["'\s:=]+["']?(6L[a-zA-Z0-9_-]{38})/gi, severity: 'info', note: 'Public site key - not a secret but reveals reCAPTCHA usage and version' },

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
    { name: 'OpenAI Project Key', pattern: /sk-proj-[a-zA-Z0-9_-]{80,}/g },

    // Anthropic
    { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9_-]{40,}/g },

    // Azure
    { name: 'Azure Subscription Key', pattern: /[a-f0-9]{32}(?=.*(?:azure|cognitive|ocp-apim))/gi },
    { name: 'Azure Storage Key', pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};/g },
    { name: 'Azure SAS Token', pattern: /[?&]sig=[A-Za-z0-9%+/=]{43,}/g },
    { name: 'Azure AD Client Secret', pattern: /(?:client_secret|clientSecret)["'\s:=]+["']?([a-zA-Z0-9~._-]{34,})/gi },

    // Cloudflare
    { name: 'Cloudflare API Key', pattern: /(?:cf_api_key|cloudflare)["'\s:=]+["']?([a-f0-9]{37})/gi },
    { name: 'Cloudflare API Token', pattern: /[a-zA-Z0-9_-]{40}(?=.*cloudflare)/gi },

    // Supabase
    { name: 'Supabase Service Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6/g },
    { name: 'Supabase Anon Key', pattern: /(?:supabase.*(?:anon|key))["'\s:=]+["']?(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi, severity: 'info', note: 'Anon key is public by design but reveals Supabase usage' },

    // Vercel
    { name: 'Vercel Token', pattern: /(?:vercel_token|VERCEL_TOKEN)["'\s:=]+["']?([a-zA-Z0-9]{24})/gi },

    // DigitalOcean
    { name: 'DigitalOcean Token', pattern: /dop_v1_[a-f0-9]{64}/g },
    { name: 'DigitalOcean Spaces Key', pattern: /(?:SPACES_KEY|do_spaces)["'\s:=]+["']?([A-Z0-9]{20})/gi },

    // Datadog
    { name: 'Datadog API Key', pattern: /(?:dd_api_key|datadog.*api.*key)["'\s:=]+["']?([a-f0-9]{32})/gi },
    { name: 'Datadog App Key', pattern: /(?:dd_app_key|datadog.*app.*key)["'\s:=]+["']?([a-f0-9]{40})/gi },

    // Sentry
    { name: 'Sentry DSN', pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io\/\d+/g },
    { name: 'Sentry Auth Token', pattern: /sntrys_[a-zA-Z0-9_]{60,}/g },

    // PlanetScale
    { name: 'PlanetScale Password', pattern: /pscale_pw_[a-zA-Z0-9_-]{43}/g },
    { name: 'PlanetScale Token', pattern: /pscale_tkn_[a-zA-Z0-9_-]{43}/g },

    // Linear
    { name: 'Linear API Key', pattern: /lin_api_[a-zA-Z0-9]{40}/g },

    // Notion
    { name: 'Notion Integration Token', pattern: /(?:ntn_|secret_)[a-zA-Z0-9]{43}/g },

    // Airtable
    { name: 'Airtable API Key', pattern: /pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}/g },

    // Contentful
    { name: 'Contentful Delivery Token', pattern: /(?:contentful|CONTENTFUL).*["'\s:=]+["']?([a-zA-Z0-9_-]{43})/gi },

    // Postmark
    { name: 'Postmark Server Token', pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=.*postmark)/gi },

    // Resend
    { name: 'Resend API Key', pattern: /re_[a-zA-Z0-9]{30,}/g },

    // Clerk
    { name: 'Clerk Secret Key', pattern: /sk_live_[a-zA-Z0-9]{27,}/g },
    { name: 'Clerk Publishable Key', pattern: /pk_live_[a-zA-Z0-9]{27,}/g, severity: 'info', note: 'Public key - not a secret' },

    // Auth0
    { name: 'Auth0 Client Secret', pattern: /(?:auth0.*(?:client_secret|clientSecret))["'\s:=]+["']?([a-zA-Z0-9_-]{32,})/gi },

    // MongoDB
    { name: 'MongoDB Connection', pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>{}`]+/g },

    // PostgreSQL / MySQL connection strings
    { name: 'Database Connection', pattern: /(?:postgres|mysql|mariadb):\/\/[^\s"'<>{}`]+/g },

    // Redis
    { name: 'Redis Connection', pattern: /redis(?:s)?:\/\/[^\s"'<>{}`]+/g },

    // Grafana
    { name: 'Grafana API Key', pattern: /eyJrIjoi[a-zA-Z0-9_-]{30,}/g },
    { name: 'Grafana Service Token', pattern: /glsa_[a-zA-Z0-9_]{32,}/g },

    // HashiCorp Vault / Terraform
    { name: 'Vault Token', pattern: /hvs\.[a-zA-Z0-9_-]{24,}/g },
    { name: 'Terraform Cloud Token', pattern: /(?:atlas_token|TFE_TOKEN)["'\s:=]+["']?([a-zA-Z0-9.]{14,})/gi },

    // Doppler
    { name: 'Doppler Token', pattern: /dp\.(?:st|ct|sa|scrt)\.[a-zA-Z0-9_-]{40,}/g },

    // LaunchDarkly
    { name: 'LaunchDarkly SDK Key', pattern: /sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g },

    // Intercom
    { name: 'Intercom Access Token', pattern: /dG9rOi[a-zA-Z0-9_-]{30,}/g },

    // HubSpot
    { name: 'HubSpot API Key', pattern: /(?:hapikey|hubspot.*api.*key)["'\s:=]+["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi },
    { name: 'HubSpot Private App Token', pattern: /pat-(?:na1|eu1)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g },

    // Jira / Atlassian
    { name: 'Atlassian API Token', pattern: /(?:atlassian|jira|confluence).*(?:token|api_key)["'\s:=]+["']?([a-zA-Z0-9]{24,})/gi },

    // GitLab
    { name: 'GitLab Token', pattern: /glpat-[a-zA-Z0-9_-]{20}/g },
    { name: 'GitLab CI Token', pattern: /glcbt-[a-zA-Z0-9_-]{20,}/g },

    // Bitbucket
    { name: 'Bitbucket App Password', pattern: /(?:bitbucket.*(?:password|token|secret))["'\s:=]+["']?([a-zA-Z0-9]{18,})/gi },

    // Telegram
    { name: 'Telegram Bot Token', pattern: /\d{8,10}:[A-Za-z0-9_-]{35}/g },

    // Coinbase
    { name: 'Coinbase API Key', pattern: /(?:coinbase).*["'\s:=]+["']?([a-zA-Z0-9]{16,})/gi },

    // Plaid
    { name: 'Plaid Client ID', pattern: /(?:plaid.*client.id)["'\s:=]+["']?([a-f0-9]{24})/gi },
    { name: 'Plaid Secret', pattern: /(?:plaid.*secret)["'\s:=]+["']?([a-f0-9]{30})/gi },

    // Pinecone
    { name: 'Pinecone API Key', pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=.*pinecone)/gi },

    // Pusher
    { name: 'Pusher App Secret', pattern: /(?:pusher.*secret)["'\s:=]+["']?([a-f0-9]{20})/gi },

    // Mixpanel
    { name: 'Mixpanel Secret', pattern: /(?:mixpanel.*secret)["'\s:=]+["']?([a-f0-9]{32})/gi },

    // Amplitude
    { name: 'Amplitude API Key', pattern: /(?:amplitude.*(?:api_key|apiKey))["'\s:=]+["']?([a-f0-9]{32})/gi },

    // Segment Write Key
    { name: 'Segment Write Key', pattern: /(?:segment.*write.*key)["'\s:=]+["']?([a-zA-Z0-9]{22,})/gi },

    // Mailgun
    { name: 'Mailgun API Key', pattern: /key-[a-f0-9]{32}/g },

    // Braintree
    { name: 'Braintree Access Token', pattern: /access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}/g },

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
  const scannedScriptUrls = new Set();

  function scanSingleScript(src) {
    if (!src || !src.startsWith(location.origin) || scannedScriptUrls.has(src)) return;
    scannedScriptUrls.add(src);
    fetch(src)
      .then(r => r.text())
      .then(content => {
        scanForSecrets(content, src);
        scanForCloudStorage(content, src);
        scanForGraphQL(content, src);
      })
      .catch(() => {});
  }

  function scanExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => scanSingleScript(script.src));
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

  // CDN domains known to allow user-controlled content (CSP bypasses)
  const CSP_BYPASS_DOMAINS = [
    'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
    'raw.githubusercontent.com', 'gist.githubusercontent.com',
    'ajax.googleapis.com', 'accounts.google.com',
    '*.googleapis.com', '*.gstatic.com', '*.google.com',
    'cdn.firebase.com', 'firebaseapp.com',
    'storage.googleapis.com', 's3.amazonaws.com',
    'docs.google.com', 'translate.googleapis.com',
  ];

  function parseCSP(cspString) {
    const directives = {};
    cspString.split(';').forEach(part => {
      const trimmed = part.trim();
      if (!trimmed) return;
      const [name, ...values] = trimmed.split(/\s+/);
      directives[name.toLowerCase()] = values;
    });
    return directives;
  }

  function analyzeCSP(csp) {
    const findings = [];
    const directives = parseCSP(csp);
    const scriptSrc = directives['script-src'] || directives['default-src'] || [];
    const objectSrc = directives['object-src'];
    const baseSrc = directives['base-uri'];
    const frameAnc = directives['frame-ancestors'];

    // unsafe-inline in script-src
    if (scriptSrc.includes("'unsafe-inline'") && !scriptSrc.some(v => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
      findings.push({ issue: "unsafe-inline in script-src (no nonce/hash)", severity: 'high',
        description: 'Allows inline <script> and event handlers, defeating XSS protection' });
    }
    // unsafe-eval
    if (scriptSrc.includes("'unsafe-eval'")) {
      findings.push({ issue: "unsafe-eval in script-src", severity: 'high',
        description: 'Allows eval(), Function(), setTimeout(string) - enables code injection' });
    }
    // data: URI in script-src
    if (scriptSrc.includes('data:')) {
      findings.push({ issue: "data: URI in script-src", severity: 'high',
        description: 'Allows <script src="data:text/javascript,alert(1)"> - trivial XSS bypass' });
    }
    // Wildcard * in script-src
    if (scriptSrc.includes('*')) {
      findings.push({ issue: "Wildcard * in script-src", severity: 'critical',
        description: 'Allows loading scripts from ANY origin' });
    }
    // CDN bypass domains
    for (const src of scriptSrc) {
      const srcLower = src.toLowerCase().replace(/^https?:\/\//, '');
      for (const bypass of CSP_BYPASS_DOMAINS) {
        if (bypass.startsWith('*.')) {
          if (srcLower.endsWith(bypass.slice(1)) || srcLower === bypass.slice(2)) {
            findings.push({ issue: `CDN bypass: ${src}`, severity: 'high',
              description: `${src} may host user-controlled content usable for CSP bypass` });
            break;
          }
        } else if (srcLower === bypass || srcLower.endsWith('/' + bypass)) {
          findings.push({ issue: `CDN bypass: ${src}`, severity: 'high',
            description: `${src} may host user-controlled content usable for CSP bypass` });
          break;
        }
      }
    }
    // Missing object-src
    if (!objectSrc && !directives['default-src']) {
      findings.push({ issue: "Missing object-src", severity: 'medium',
        description: 'No object-src restriction - Flash/plugin-based XSS possible' });
    }
    // Missing base-uri
    if (!baseSrc) {
      findings.push({ issue: "Missing base-uri", severity: 'medium',
        description: 'No base-uri restriction - <base> tag injection can redirect relative URLs' });
    }
    // Missing frame-ancestors
    if (!frameAnc) {
      findings.push({ issue: "Missing frame-ancestors", severity: 'medium',
        description: 'No frame-ancestors - clickjacking not prevented by CSP' });
    }
    // Missing default-src
    if (!directives['default-src']) {
      findings.push({ issue: "Missing default-src", severity: 'low',
        description: 'No default-src fallback for uncovered directives' });
    }
    return findings;
  }

  function scoreSecurityHeaders(headers) {
    let score = 0;
    const checks = [];
    const csp = headers['content-security-policy'];
    const hsts = headers['strict-transport-security'];
    const xcto = headers['x-content-type-options'];
    const xfo = headers['x-frame-options'];
    const refp = headers['referrer-policy'];
    const permp = headers['permissions-policy'] || headers['feature-policy'];
    const coop = headers['cross-origin-opener-policy'];
    const corp = headers['cross-origin-resource-policy'];

    // CSP (max 30)
    if (csp) {
      const cspIssues = analyzeCSP(csp);
      const critical = cspIssues.filter(f => f.severity === 'critical').length;
      const high = cspIssues.filter(f => f.severity === 'high').length;
      if (critical === 0 && high === 0) { score += 30; checks.push({ header: 'CSP', score: 30, max: 30, status: 'good' }); }
      else if (critical === 0) { score += 15; checks.push({ header: 'CSP', score: 15, max: 30, status: 'weak' }); }
      else { score += 5; checks.push({ header: 'CSP', score: 5, max: 30, status: 'bad' }); }
    } else {
      checks.push({ header: 'CSP', score: 0, max: 30, status: 'missing' });
    }
    // HSTS (max 20)
    if (hsts && location.protocol === 'https:') {
      let hstsScore = 10;
      if (/includeSubdomains/i.test(hsts)) hstsScore += 5;
      if (/preload/i.test(hsts)) hstsScore += 5;
      score += hstsScore;
      checks.push({ header: 'HSTS', score: hstsScore, max: 20, status: hstsScore >= 15 ? 'good' : 'weak' });
    } else if (location.protocol === 'https:') {
      checks.push({ header: 'HSTS', score: 0, max: 20, status: 'missing' });
    } else {
      score += 20; // N/A for HTTP
      checks.push({ header: 'HSTS', score: 20, max: 20, status: 'na' });
    }
    // X-Content-Type-Options (max 10)
    if (xcto?.toLowerCase() === 'nosniff') { score += 10; checks.push({ header: 'X-Content-Type-Options', score: 10, max: 10, status: 'good' }); }
    else { checks.push({ header: 'X-Content-Type-Options', score: 0, max: 10, status: 'missing' }); }
    // X-Frame-Options or CSP frame-ancestors (max 10)
    if (xfo || csp?.includes('frame-ancestors')) { score += 10; checks.push({ header: 'Clickjacking Protection', score: 10, max: 10, status: 'good' }); }
    else { checks.push({ header: 'Clickjacking Protection', score: 0, max: 10, status: 'missing' }); }
    // Referrer-Policy (max 10)
    if (refp) { score += 10; checks.push({ header: 'Referrer-Policy', score: 10, max: 10, status: 'good' }); }
    else { checks.push({ header: 'Referrer-Policy', score: 0, max: 10, status: 'missing' }); }
    // Permissions-Policy (max 10)
    if (permp) { score += 10; checks.push({ header: 'Permissions-Policy', score: 10, max: 10, status: 'good' }); }
    else { checks.push({ header: 'Permissions-Policy', score: 0, max: 10, status: 'missing' }); }
    // COOP (max 5)
    if (coop) { score += 5; checks.push({ header: 'COOP', score: 5, max: 5, status: 'good' }); }
    else { checks.push({ header: 'COOP', score: 0, max: 5, status: 'missing' }); }
    // CORP (max 5)
    if (corp) { score += 5; checks.push({ header: 'CORP', score: 5, max: 5, status: 'good' }); }
    else { checks.push({ header: 'CORP', score: 0, max: 5, status: 'missing' }); }

    let grade;
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 65) grade = 'B';
    else if (score >= 50) grade = 'C';
    else if (score >= 35) grade = 'D';
    else grade = 'F';

    return { score, grade, checks };
  }

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

      // === CSP Analysis ===
      const csp = headers['content-security-policy'];
      if (!csp) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Content-Security-Policy',
          severity: 'medium',
          description: 'No CSP header - XSS attacks easier to exploit',
          url: location.href,
        });
      } else {
        const cspIssues = analyzeCSP(csp);
        for (const issue of cspIssues) {
          reportFinding('WEAK_CSP', {
            header: 'Content-Security-Policy',
            issue: issue.issue,
            severity: issue.severity,
            description: issue.description,
            url: location.href,
            value: csp.substring(0, 500),
          });
        }
      }

      // === CORS ===
      const cors = headers['access-control-allow-origin'];
      const corsCredentials = headers['access-control-allow-credentials'];
      if (cors === '*') {
        const severity = corsCredentials === 'true' ? 'critical' : 'medium';
        reportFinding('PERMISSIVE_CORS', {
          header: 'Access-Control-Allow-Origin',
          value: cors,
          credentials: corsCredentials,
          severity: severity,
          description: corsCredentials === 'true'
            ? 'CORS allows any origin WITH credentials - full data theft possible'
            : 'CORS allows any origin - may leak sensitive data',
          url: location.href,
        });
      }

      // === Clickjacking ===
      const xfo = headers['x-frame-options'];
      if (!xfo && !csp?.includes('frame-ancestors')) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'X-Frame-Options',
          severity: 'low',
          description: 'No clickjacking protection',
          url: location.href,
        });
      }

      // === HSTS ===
      const hsts = headers['strict-transport-security'];
      if (!hsts && location.protocol === 'https:') {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Strict-Transport-Security',
          severity: 'low',
          description: 'No HSTS - vulnerable to SSL stripping',
          url: location.href,
        });
      }

      // === X-Content-Type-Options ===
      if (!headers['x-content-type-options']) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'X-Content-Type-Options',
          severity: 'low',
          description: 'Missing nosniff - MIME type sniffing possible',
          url: location.href,
        });
      }

      // === Referrer-Policy ===
      if (!headers['referrer-policy']) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Referrer-Policy',
          severity: 'low',
          description: 'No Referrer-Policy - full URL may leak in Referer header',
          url: location.href,
        });
      }

      // === Permissions-Policy ===
      if (!headers['permissions-policy'] && !headers['feature-policy']) {
        reportFinding('MISSING_SECURITY_HEADER', {
          header: 'Permissions-Policy',
          severity: 'info',
          description: 'No Permissions-Policy - browser features not restricted',
          url: location.href,
        });
      }

      // === Info leak headers ===
      const server = headers['server'];
      const poweredBy = headers['x-powered-by'];
      const debugToken = headers['x-debug-token'] || headers['x-debug-token-link'];
      const backendServer = headers['x-backend-server'];
      const chromeLogger = headers['x-chromelogger-data'] || headers['x-chromephp-data'];

      if (server && /\d/.test(server)) {
        reportFinding('SERVER_DISCLOSURE', { header: 'Server', value: server, severity: 'info',
          description: 'Server version disclosed', url: location.href });
      }
      if (poweredBy) {
        reportFinding('SERVER_DISCLOSURE', { header: 'X-Powered-By', value: poweredBy, severity: 'info',
          description: 'Technology stack disclosed', url: location.href });
      }
      if (debugToken) {
        reportFinding('SERVER_DISCLOSURE', { header: 'X-Debug-Token', value: debugToken, severity: 'high',
          description: 'Symfony debug profiler token exposed - may reveal sensitive debug data', url: location.href });
      }
      if (backendServer) {
        reportFinding('SERVER_DISCLOSURE', { header: 'X-Backend-Server', value: backendServer, severity: 'medium',
          description: 'Internal backend server hostname disclosed', url: location.href });
      }
      if (chromeLogger) {
        reportFinding('SERVER_DISCLOSURE', { header: 'X-ChromeLogger-Data', value: '(base64 data)', severity: 'high',
          description: 'ChromeLogger debug data exposed - may contain SQL queries, variables', url: location.href });
      }

      // === Security Score ===
      const headerScore = scoreSecurityHeaders(headers);
      safeSendMessage({
        type: 'securityScore',
        score: headerScore.score,
        grade: headerScore.grade,
        checks: headerScore.checks,
        url: location.href,
      });

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

    const sensitivePatterns = [
      /session/i, /token/i, /auth/i, /jwt/i, /api.?key/i,
      /csrf/i, /xsrf/i, /login/i, /user/i, /admin/i
    ];

    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.split('=');
      if (!name) continue;
      const value = valueParts.join('=');
      const isSensitive = sensitivePatterns.some(p => p.test(name));

      // If we can read it via JS, it's not HttpOnly
      if (isSensitive) {
        reportFinding('INSECURE_COOKIE', {
          cookie: name.trim(),
          issue: 'Missing HttpOnly flag',
          severity: 'medium',
          description: `Sensitive cookie "${name.trim()}" readable by JS - vulnerable to XSS theft`,
          url: location.href,
        });
      }

      // __Host- prefix validation: must have Secure, no Domain, Path=/
      const trimName = name.trim();
      if (trimName.startsWith('__Host-')) {
        // If we can read it, it's not HttpOnly (already flagged above if sensitive)
        // __Host- cookies must be set with Secure - if site is HTTP, it's wrong
        if (location.protocol === 'http:') {
          reportFinding('INSECURE_COOKIE', {
            cookie: trimName,
            issue: '__Host- prefix on HTTP',
            severity: 'high',
            description: `__Host- cookie "${trimName}" on HTTP violates prefix requirements (must be Secure)`,
            url: location.href,
          });
        }
      }

      // __Secure- prefix validation
      if (trimName.startsWith('__Secure-') && location.protocol === 'http:') {
        reportFinding('INSECURE_COOKIE', {
          cookie: trimName,
          issue: '__Secure- prefix on HTTP',
          severity: 'high',
          description: `__Secure- cookie "${trimName}" on HTTP violates prefix requirements`,
          url: location.href,
        });
      }

      // Detect JWTs in cookie values (passive JWT detection)
      if (value && isJWT(value)) {
        analyzeJWT(value, `cookie[${trimName}]`);
      }
    }

    // Cookies over HTTP
    if (location.protocol === 'http:' && cookies.length > 0) {
      reportFinding('INSECURE_COOKIE', {
        issue: 'Cookies over HTTP',
        severity: 'high',
        description: 'All cookies transmitted over unencrypted HTTP - session hijacking trivial',
        url: location.href,
        cookieCount: cookies.length,
      });
    }

    // Enhanced: use cookies API via background for SameSite/Secure/Domain analysis
    safeSendMessage({ type: 'auditCookiesRequest', url: location.href }, (cookieDetails) => {
      if (!cookieDetails || !Array.isArray(cookieDetails)) return;
      for (const c of cookieDetails) {
        const isSens = sensitivePatterns.some(p => p.test(c.name));
        // Missing Secure flag on HTTPS
        if (!c.secure && location.protocol === 'https:' && isSens) {
          reportFinding('INSECURE_COOKIE', {
            cookie: c.name,
            issue: 'Missing Secure flag',
            severity: 'medium',
            description: `Sensitive cookie "${c.name}" can be sent over HTTP (no Secure flag)`,
            url: location.href,
          });
        }
        // Missing or weak SameSite
        if (isSens && (!c.sameSite || c.sameSite === 'no_restriction')) {
          reportFinding('INSECURE_COOKIE', {
            cookie: c.name,
            issue: `SameSite=${c.sameSite || 'not set'}`,
            severity: 'medium',
            description: `Sensitive cookie "${c.name}" has no SameSite restriction - CSRF possible`,
            url: location.href,
          });
        }
        // Overly broad domain
        if (c.domain && c.domain.startsWith('.') && isSens) {
          const dotCount = c.domain.split('.').length - 1;
          if (dotCount <= 2) { // e.g., .example.com covers all subdomains
            reportFinding('INSECURE_COOKIE', {
              cookie: c.name,
              issue: `Broad domain scope: ${c.domain}`,
              severity: 'low',
              description: `Sensitive cookie "${c.name}" scoped to ${c.domain} - readable by all subdomains`,
              url: location.href,
            });
          }
        }
      }
    });
  }

  // ============================================================
  // OPEN REDIRECT DETECTION
  // ============================================================

  function checkOpenRedirect() {
    const params = new URLSearchParams(location.search);
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo',
                           'goto', 'target', 'destination', 'redir', 'redirect_uri',
                           'continue', 'callback', 'forward', 'out', 'link'];

    // Skip known third-party service domains where URL params are contextual, not redirects
    const benignHosts = /giosg\.com|intercom\.io|zendesk\.com|livechat|tawk\.to|crisp\.chat|drift\.com|hubspot\.com|freshdesk\.com|olark\.com|smartsupp\.com|tidio\.co/;
    if (benignHosts.test(location.hostname)) return;

    for (const param of redirectParams) {
      const value = params.get(param);
      if (value) {
        // Check if it looks like a URL
        if (value.startsWith('http') || value.startsWith('//') || value.startsWith('/')) {
          // Skip if the URL param just points back to the current site's main domain
          try {
            const decoded = decodeURIComponent(decodeURIComponent(value));
            const tabHost = (document.referrer && new URL(document.referrer).hostname) || '';
            const valHost = decoded.startsWith('http') ? new URL(decoded).hostname : '';
            if (valHost && tabHost && (valHost === tabHost || valHost.endsWith('.' + tabHost) || tabHost.endsWith('.' + valHost))) continue;
          } catch (e) { /* proceed with report */ }
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
  // SUSPICIOUS COMMENTS SCANNER
  // ============================================================

  function scanSuspiciousComments() {
    const suspiciousPatterns = [
      { pattern: /\bTODO\b/i, label: 'TODO' },
      { pattern: /\bFIXME\b/i, label: 'FIXME' },
      { pattern: /\bHACK\b/i, label: 'HACK' },
      { pattern: /\bBUG\b/i, label: 'BUG' },
      { pattern: /\bXXX\b/i, label: 'XXX' },
      { pattern: /\bpassword/i, label: 'password reference' },
      { pattern: /\bcredential/i, label: 'credential reference' },
      { pattern: /\bsecret/i, label: 'secret reference' },
      { pattern: /\bapi[_-]?key/i, label: 'API key reference' },
      { pattern: /\btoken/i, label: 'token reference' },
      { pattern: /\bdebug/i, label: 'debug reference' },
      { pattern: /\badmin/i, label: 'admin reference' },
      { pattern: /\broot\b/i, label: 'root reference' },
      { pattern: /\bhardcoded/i, label: 'hardcoded reference' },
      { pattern: /\btemporary\b/i, label: 'temporary reference' },
      { pattern: /\bworkaround\b/i, label: 'workaround reference' },
      { pattern: /\binsecure\b/i, label: 'insecure reference' },
      { pattern: /\bvulnerab/i, label: 'vulnerability reference' },
    ];

    const found = [];

    // 1. Scan HTML comments (<!-- ... -->)
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
    let node;
    while ((node = walker.nextNode())) {
      const text = node.textContent.trim();
      if (!text || text.length < 4) continue;
      // Skip conditional comments (IE), common CMS/GTM markers
      if (/^\[if |^google|^gtm|^fb-|^ko /.test(text)) continue;
      for (const { pattern, label } of suspiciousPatterns) {
        if (pattern.test(text)) {
          found.push({
            context: 'HTML comment',
            keyword: label,
            preview: text.substring(0, 200),
            parent: node.parentElement ? node.parentElement.tagName : 'unknown',
          });
          break; // one finding per comment
        }
      }
    }

    // 2. Scan inline <script> comments (// and /* */)
    const scripts = document.querySelectorAll('script:not([src])');
    const commentRegex = /\/\/[^\n]*|\/\*[\s\S]*?\*\//g;
    for (const script of scripts) {
      const src = script.textContent || '';
      if (src.length < 10) continue;
      // Skip GTM/analytics inline scripts
      if (/google_tag_manager|googletagmanager|gtag\(|fbq\(|_gaq/.test(src.substring(0, 500))) continue;
      let m;
      while ((m = commentRegex.exec(src)) !== null) {
        const comment = m[0];
        // Skip protocol-relative URLs falsely matched as // comments
        if (/^\/\/[\w.-]+\.(com|net|org|io|fi|de|uk|se|no|eu|co)\b/.test(comment)) continue;
        // Skip URLs embedded in JSON strings matched as // comments
        if (/^\/\/[a-z][\w.-]*\//.test(comment) && !/\s/.test(comment.substring(0, 40))) continue;
        for (const { pattern, label } of suspiciousPatterns) {
          if (pattern.test(comment)) {
            found.push({
              context: 'JS comment',
              keyword: label,
              preview: comment.substring(0, 200),
              parent: 'SCRIPT',
            });
            break;
          }
        }
      }
    }

    // Report grouped findings
    if (found.length > 0) {
      reportFinding('SUSPICIOUS_COMMENTS', {
        severity: 'info',
        description: `Found ${found.length} suspicious comment(s) with sensitive keywords`,
        url: location.href,
        comments: found.slice(0, 50), // cap at 50
      });
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

        // Passive scans that don't generate suspicious traffic:
        analyzeSecurityHeaders();  // One HEAD request - minimal WAF risk, high value
        auditCookies();            // No network requests - reads document.cookie + cookies API
        analyzeJWTs();             // No network requests - reads localStorage/sessionStorage
        checkOpenRedirect();       // No network requests - reads URL params
        scanSuspiciousComments();  // No network requests - reads DOM comments

        // NOTE: These active scans remain DISABLED by default to avoid WAF detection
        // They can be triggered manually via popup buttons:
        // - detectSourceMaps()        -> "Source Maps" button
        // - checkSensitivePaths()     -> "Sensitive Paths" button
        // - scanExternalScripts()     -> "Secrets Scan" button
        // - detectMixedContent()      -> Part of "Full Scan"
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

  // Inject DOM hooks (innerHTML/eval/document.write monitoring) into MAIN world
  function injectDOMHooks() {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('dom-hooks.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      console.warn('[Lonkero] Failed to inject DOM hooks:', e);
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
    // Whitelist fields to prevent untrusted page data from polluting extension state
    if (event.data?.type === '__lonkero_finding__') {
      const finding = event.data.finding;
      if (finding && finding.type) {
        reportFinding(String(finding.type).slice(0, 100), {
          url: finding.url ? String(finding.url).slice(0, 2000) : location.href,
          severity: finding.severity ? String(finding.severity).slice(0, 20) : undefined,
          evidence: finding.evidence ? String(finding.evidence).slice(0, 500) : undefined,
          parameter: finding.parameter ? String(finding.parameter).slice(0, 200) : undefined,
          context: finding.context ? String(finding.context).slice(0, 500) : undefined,
          sink: finding.sink ? String(finding.sink).slice(0, 100) : undefined,
          source: finding.source ? String(finding.source).slice(0, 200) : undefined,
          element: finding.element ? String(finding.element).slice(0, 100) : undefined,
          value: finding.value ? String(finding.value).slice(0, 500) : undefined,
          valuePreview: finding.valuePreview ? String(finding.valuePreview).slice(0, 200) : undefined,
          codePreview: finding.codePreview ? String(finding.codePreview).slice(0, 200) : undefined,
          version: finding.version ? String(finding.version).slice(0, 50) : undefined,
          library: finding.library ? String(finding.library).slice(0, 100) : undefined,
          description: finding.description ? String(finding.description).slice(0, 500) : undefined,
          category: finding.category ? String(finding.category).slice(0, 100) : undefined,
          proof: finding.proof ? String(finding.proof).slice(0, 500) : undefined,
        });
      }
    }

    // Handle framework scanner findings
    if (event.data?.type === '__lonkero_framework_finding__') {
      const finding = event.data.finding;
      if (finding && finding.type) {
        reportFinding(String(finding.type).slice(0, 100), {
          url: finding.url ? String(finding.url).slice(0, 2000) : location.href,
          severity: finding.severity ? String(finding.severity).slice(0, 20) : undefined,
          evidence: finding.evidence ? String(finding.evidence).slice(0, 500) : undefined,
          version: finding.version ? String(finding.version).slice(0, 50) : undefined,
          description: finding.description ? String(finding.description).slice(0, 500) : undefined,
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
        injectDOMHooks();
        init();
        injectFormFuzzer();
        injectGraphQLFuzzer();
        injectMerlin();
        injectXSSScanner();
        injectCMSScanner();
      });
    } else {
      injectRequestInterceptors();
      injectDOMHooks();
      init();
      injectFormFuzzer();
      injectGraphQLFuzzer();
      injectMerlin();
      injectXSSScanner();
      injectCMSScanner();
    }

    // Watch for dynamically added scripts (catches lazy-loaded chunks in Next.js, webpack, etc.)
    // Also re-inject on SPA navigation
    let lastUrl = location.href;
    new MutationObserver((mutations) => {
      // Scan dynamically added first-party scripts for secrets
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeName === 'SCRIPT' && node.src) {
            scanSingleScript(node.src);
          }
        }
      }

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
