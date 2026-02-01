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
 * - Real-time vulnerability highlighting
 * - Bidirectional CLI communication
 */

(function() {
  'use strict';

  // Avoid double injection
  if (window.__lonkeroInjected) return;
  window.__lonkeroInjected = true;

  // ============================================================
  // REAL-TIME VULNERABILITY HIGHLIGHTING
  // ============================================================

  const SEVERITY_COLORS = {
    critical: { border: '#dc2626', bg: 'rgba(220, 38, 38, 0.15)', shadow: 'rgba(220, 38, 38, 0.5)' },
    high:     { border: '#ea580c', bg: 'rgba(234, 88, 12, 0.15)', shadow: 'rgba(234, 88, 12, 0.4)' },
    medium:   { border: '#ca8a04', bg: 'rgba(202, 138, 4, 0.15)', shadow: 'rgba(202, 138, 4, 0.3)' },
    low:      { border: '#2563eb', bg: 'rgba(37, 99, 235, 0.15)', shadow: 'rgba(37, 99, 235, 0.3)' },
    info:     { border: '#6b7280', bg: 'rgba(107, 114, 128, 0.1)', shadow: 'rgba(107, 114, 128, 0.2)' }
  };

  class VulnerabilityHighlighter {
    constructor() {
      this.findings = new Map();
      this.riskParams = new Map();
      this.stylesInjected = false;
    }

    injectStyles() {
      if (this.stylesInjected) return;
      this.stylesInjected = true;

      const style = document.createElement('style');
      style.id = 'lonkero-highlight-styles';
      style.textContent = `
        .lonkero-vuln {
          position: relative !important;
          transition: all 0.3s ease !important;
        }
        .lonkero-vuln-critical {
          outline: 3px solid #dc2626 !important;
          box-shadow: 0 0 12px rgba(220, 38, 38, 0.6) !important;
          background: rgba(220, 38, 38, 0.1) !important;
        }
        .lonkero-vuln-high {
          outline: 3px solid #ea580c !important;
          box-shadow: 0 0 10px rgba(234, 88, 12, 0.5) !important;
          background: rgba(234, 88, 12, 0.1) !important;
        }
        .lonkero-vuln-medium {
          outline: 2px solid #ca8a04 !important;
          background: rgba(202, 138, 4, 0.1) !important;
        }
        .lonkero-vuln-low {
          outline: 2px dashed #2563eb !important;
        }
        .lonkero-risk-high {
          outline: 2px dashed #f59e0b !important;
        }
        .lonkero-risk-medium {
          outline: 1px dashed #6b7280 !important;
        }

        @keyframes lonkero-pulse {
          0% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.7); }
          70% { box-shadow: 0 0 0 15px rgba(220, 38, 38, 0); }
          100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0); }
        }
        .lonkero-vuln-new {
          animation: lonkero-pulse 1s ease-out 3;
        }

        .lonkero-tooltip {
          position: fixed;
          z-index: 2147483647;
          background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
          color: #f9fafb;
          padding: 12px 16px;
          border-radius: 8px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 13px;
          max-width: 400px;
          box-shadow: 0 20px 50px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.1);
          pointer-events: none;
          opacity: 0;
          transform: translateY(5px);
          transition: opacity 0.2s, transform 0.2s;
        }
        .lonkero-tooltip.visible {
          opacity: 1;
          transform: translateY(0);
        }
        .lonkero-tooltip-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 8px;
          padding-bottom: 8px;
          border-bottom: 1px solid #374151;
        }
        .lonkero-tooltip-severity {
          padding: 3px 8px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .lonkero-tooltip-severity.critical { background: #dc2626; }
        .lonkero-tooltip-severity.high { background: #ea580c; }
        .lonkero-tooltip-severity.medium { background: #ca8a04; }
        .lonkero-tooltip-severity.low { background: #2563eb; }
        .lonkero-tooltip-type {
          font-weight: 600;
          font-size: 14px;
        }
        .lonkero-tooltip-detail {
          color: #9ca3af;
          font-size: 12px;
          margin-top: 6px;
        }
        .lonkero-tooltip-param {
          display: inline-block;
          background: #374151;
          padding: 2px 6px;
          border-radius: 3px;
          font-family: monospace;
          font-size: 12px;
          color: #fbbf24;
        }
        .lonkero-tooltip-evidence {
          margin-top: 8px;
          padding: 8px;
          background: #111827;
          border-radius: 4px;
          font-family: monospace;
          font-size: 11px;
          color: #d1d5db;
          max-height: 100px;
          overflow: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }

        .lonkero-badge {
          position: absolute;
          top: -10px;
          right: -10px;
          min-width: 20px;
          height: 20px;
          padding: 0 6px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 11px;
          font-weight: bold;
          color: white;
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          z-index: 2147483646;
          box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .lonkero-scan-indicator {
          position: fixed;
          bottom: 20px;
          right: 20px;
          background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
          color: white;
          padding: 12px 20px;
          border-radius: 8px;
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          font-size: 13px;
          z-index: 2147483647;
          box-shadow: 0 10px 40px rgba(0,0,0,0.3);
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .lonkero-scan-indicator.hidden { display: none; }
        .lonkero-scan-spinner {
          width: 16px;
          height: 16px;
          border: 2px solid #374151;
          border-top-color: #3b82f6;
          border-radius: 50%;
          animation: lonkero-spin 1s linear infinite;
        }
        @keyframes lonkero-spin {
          to { transform: rotate(360deg); }
        }
      `;
      (document.head || document.documentElement).appendChild(style);
    }

    highlightFinding(finding) {
      this.injectStyles();

      let element = null;

      // Try selector first
      if (finding.element_selector) {
        try {
          element = document.querySelector(finding.element_selector);
        } catch (e) {}
      }

      // Try by parameter name
      if (!element && finding.parameter) {
        const selectors = [
          `input[name="${finding.parameter}"]`,
          `textarea[name="${finding.parameter}"]`,
          `select[name="${finding.parameter}"]`,
          `input[id="${finding.parameter}"]`,
          `[data-param="${finding.parameter}"]`,
        ];
        for (const sel of selectors) {
          try {
            element = document.querySelector(sel);
            if (element) break;
          } catch (e) {}
        }
      }

      // Try URL matching for forms
      if (!element && finding.url) {
        try {
          const url = new URL(finding.url);
          const forms = document.querySelectorAll(`form[action*="${url.pathname}"]`);
          if (forms.length > 0) element = forms[0];
        } catch (e) {}
      }

      if (!element) {
        console.log('[Lonkero] Could not find element for:', finding.parameter || finding.url);
        return;
      }

      const severity = (finding.severity || 'medium').toLowerCase();

      // Apply highlight classes
      element.classList.add('lonkero-vuln', `lonkero-vuln-${severity}`, 'lonkero-vuln-new');

      // Store finding
      const existing = this.findings.get(element) || [];
      existing.push(finding);
      this.findings.set(element, existing);

      // Add/update badge
      this.updateBadge(element, existing);

      // Setup tooltip
      this.setupTooltip(element);

      // Remove pulse animation after completion
      setTimeout(() => element.classList.remove('lonkero-vuln-new'), 3000);

      console.log('[Lonkero] Highlighted:', finding.vuln_type || finding.type, 'on', finding.parameter);
    }

    highlightRiskyParams(params) {
      this.injectStyles();

      for (const param of params) {
        if (param.risk_score < 40) continue;

        const selectors = [
          `input[name="${param.name}"]`,
          `textarea[name="${param.name}"]`,
          `select[name="${param.name}"]`,
        ];

        for (const sel of selectors) {
          try {
            const element = document.querySelector(sel);
            if (element && !element.classList.contains('lonkero-vuln')) {
              const riskClass = param.risk_score > 70 ? 'lonkero-risk-high' : 'lonkero-risk-medium';
              element.classList.add(riskClass);
              element.title = `[Lonkero] Risk: ${param.risk_score}/100 | Test for: ${param.suggested.join(', ')}`;
              this.riskParams.set(element, param);
            }
          } catch (e) {}
        }
      }
    }

    updateBadge(element, findings) {
      let badge = element.parentElement?.querySelector('.lonkero-badge');
      if (!badge) {
        badge = document.createElement('div');
        badge.className = 'lonkero-badge';
        element.style.position = 'relative';
        if (element.parentElement) {
          element.parentElement.style.position = 'relative';
          element.parentElement.appendChild(badge);
        }
      }

      const highest = this.getHighestSeverity(findings);
      badge.style.background = SEVERITY_COLORS[highest]?.border || '#6b7280';
      badge.textContent = findings.length;
    }

    setupTooltip(element) {
      if (element._lonkeroTooltip) return;
      element._lonkeroTooltip = true;

      element.addEventListener('mouseenter', (e) => this.showTooltip(e.target));
      element.addEventListener('mouseleave', () => this.hideTooltip());
      element.addEventListener('mousemove', (e) => this.moveTooltip(e));
    }

    showTooltip(element) {
      const findings = this.findings.get(element);
      if (!findings || findings.length === 0) return;

      let tooltip = document.getElementById('lonkero-tooltip');
      if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'lonkero-tooltip';
        tooltip.className = 'lonkero-tooltip';
        document.body.appendChild(tooltip);
      }

      const html = findings.map(f => {
        const sev = (f.severity || 'medium').toLowerCase();
        return `
          <div class="lonkero-tooltip-header">
            <span class="lonkero-tooltip-severity ${sev}">${f.severity || 'Medium'}</span>
            <span class="lonkero-tooltip-type">${f.vuln_type || f.type || 'Vulnerability'}</span>
          </div>
          <div class="lonkero-tooltip-detail">
            Parameter: <span class="lonkero-tooltip-param">${f.parameter || '-'}</span>
          </div>
          ${f.evidence ? `<div class="lonkero-tooltip-evidence">${this.escapeHtml(f.evidence.substring(0, 200))}</div>` : ''}
        `;
      }).join('<hr style="border:0;border-top:1px solid #374151;margin:10px 0">');

      tooltip.innerHTML = html;
      tooltip.classList.add('visible');
    }

    moveTooltip(e) {
      const tooltip = document.getElementById('lonkero-tooltip');
      if (!tooltip) return;

      const x = Math.min(e.clientX + 15, window.innerWidth - tooltip.offsetWidth - 20);
      const y = Math.min(e.clientY + 15, window.innerHeight - tooltip.offsetHeight - 20);

      tooltip.style.left = `${x}px`;
      tooltip.style.top = `${y}px`;
    }

    hideTooltip() {
      const tooltip = document.getElementById('lonkero-tooltip');
      if (tooltip) tooltip.classList.remove('visible');
    }

    getHighestSeverity(findings) {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      for (const sev of order) {
        if (findings.some(f => (f.severity || '').toLowerCase() === sev)) return sev;
      }
      return 'medium';
    }

    escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    showScanIndicator(message) {
      this.injectStyles();
      let indicator = document.getElementById('lonkero-scan-indicator');
      if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'lonkero-scan-indicator';
        indicator.className = 'lonkero-scan-indicator';
        document.body.appendChild(indicator);
      }
      indicator.innerHTML = `<div class="lonkero-scan-spinner"></div><span>${message}</span>`;
      indicator.classList.remove('hidden');
    }

    hideScanIndicator() {
      const indicator = document.getElementById('lonkero-scan-indicator');
      if (indicator) indicator.classList.add('hidden');
    }

    clear() {
      document.querySelectorAll('.lonkero-vuln, .lonkero-risk-high, .lonkero-risk-medium').forEach(el => {
        el.classList.remove('lonkero-vuln', 'lonkero-vuln-critical', 'lonkero-vuln-high',
                            'lonkero-vuln-medium', 'lonkero-vuln-low', 'lonkero-vuln-new',
                            'lonkero-risk-high', 'lonkero-risk-medium');
        el.style.outline = '';
        el.style.boxShadow = '';
        el.style.background = '';
      });
      document.querySelectorAll('.lonkero-badge').forEach(el => el.remove());
      this.findings.clear();
      this.riskParams.clear();
      this.hideScanIndicator();
    }
  }

  const highlighter = new VulnerabilityHighlighter();

  // ============================================================
  // BIDIRECTIONAL CLI COMMUNICATION
  // ============================================================

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
      case 'highlight_finding':
        highlighter.highlightFinding(msg.finding);
        sendResponse({ ok: true });
        break;

      case 'highlight_params':
        highlighter.highlightRiskyParams(msg.parameters);
        sendResponse({ ok: true });
        break;

      case 'clear_highlights':
        highlighter.clear();
        sendResponse({ ok: true });
        break;

      case 'scan_started':
        highlighter.showScanIndicator(`Scanning: ${msg.scanner || 'Initializing...'}`);
        sendResponse({ ok: true });
        break;

      case 'scan_progress':
        highlighter.showScanIndicator(`${msg.scanner || 'Scanning'} (${msg.percent}%)`);
        sendResponse({ ok: true });
        break;

      case 'scan_complete':
        highlighter.hideScanIndicator();
        sendResponse({ ok: true });
        break;

      case 'get_page_context':
        // Return rich page context for intelligent scanning
        const context = {
          url: location.href,
          title: document.title,
          forms: Array.from(document.forms).map(f => ({
            action: f.action,
            method: f.method,
            inputs: Array.from(f.elements).filter(e => e.name).map(e => ({
              name: e.name,
              type: e.type,
              id: e.id,
            }))
          })),
          links: Array.from(document.links).slice(0, 100).map(l => l.href),
          scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
          cookies: document.cookie,
          localStorage: Object.keys(localStorage),
          sessionStorage: Object.keys(sessionStorage),
        };
        sendResponse(context);
        break;
    }
    return true;
  });

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
