// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * DOM XSS Sink Monitoring — runs in MAIN world to intercept real page JS calls.
 * Patches innerHTML, document.write, eval to detect dangerous usage patterns.
 */

(function() {
  'use strict';

  const _hr = document.getElementById('__lk_c');
  const _hc = (_hr && _hr.dataset.v) || window[atob('X19sb25rZXJvS2V5')];
  if (!_hc || _hc.charCodeAt(0) !== 76 || _hc.split('-').length !== 5) { return; }
  const _hn = _hr ? _hr.dataset.n : null;
  const _he = _hr ? _hr.dataset.e : null;

  const _guardKey = Symbol.for('__lkDH_' + (_hn || ''));
  if (window[_guardKey]) return;
  window[_guardKey] = true;

  function _post(type, data) {
    if (!_he) return;
    window.postMessage({
      type: '__lonkero_finding__',
      _n: _hn, _ch: _he,
      finding: { type, ...data, url: location.href },
    }, '*');
  }

  // Monitor innerHTML assignments
  const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (origInnerHTML) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(value) {
        const v = String(value);
        if (/<script|javascript:|on\w+=/i.test(v)) {
          // Skip known-benign: GTM injects scripts via innerHTML with type="text/gtmscript"
          if (!/text\/gtmscript|google_tag_manager|googletag|gtag/.test(v)) {
            _post('DOM_XSS_POTENTIAL', {
              sink: 'innerHTML',
              element: this.tagName,
              valuePreview: v.substring(0, 200),
              severity: 'high',
            });
          }
        }
        return origInnerHTML.set.call(this, value);
      },
      get: origInnerHTML.get,
      configurable: false,
    });
  }

  // Monitor document.write
  const origWrite = document.write;
  Object.defineProperty(document, 'write', { value: function(content) {
    const v = String(content);
    if (/<script|javascript:|on\w+=/i.test(v)) {
      _post('DOM_XSS_SINK', {
        sink: 'document.write',
        valuePreview: v.substring(0, 200),
        severity: 'critical',
      });
    }
    return origWrite.apply(this, arguments);
  }, configurable: false, writable: false });

  // Monitor eval (filter known-benign callers like GTM, ad tags, analytics)
  const origEval = window.eval;
  Object.defineProperty(window, 'eval', { value: function(code) {
    const s = String(code);
    const preview = s.substring(0, 300);
    // Skip known-benign: third-party analytics, marketing, and tag managers
    const benignSDK = /google_tag_manager|googletag\.|googleads|google_ad|gtag|adsbygoogle|exponea|bloomreach|hotjar|_hj|clarity\.|mouseflow|tealium|segment\.|optimizely|abtasty|kameleoon|cookiebot|onetrust|didomi|quantcast|facebook\.net|fbq|fbevents|connect\.facebook|twitter\.com\/oct|snap\.licdn|pinterest\.com\/tag|tiktok\.com\/i18n/.test(preview);
    // Skip simple property checks like (function(){return window.X?!0:!1})()
    const benignPattern = /^\(function\(\)\{return\s+window\.\w+\?/.test(preview.replace(/\s/g, ''));
    if (!benignSDK && !benignPattern) {
      _post('DANGEROUS_EVAL', {
        codePreview: preview.substring(0, 200),
        severity: 'high',
      });
    }
    return origEval.apply(this, arguments);
  }, configurable: false, enumerable: false });

  // ============================================================
  // postMessage Enumeration
  // ============================================================

  const messageListeners = [];
  const seenOrigins = new Set();

  // Hook addEventListener to detect pages listening for 'message' events
  const origAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (type === 'message' && (this === window || this === self)) {
      const stack = new Error().stack || '';
      const fnStr = typeof listener === 'function' ? listener.toString().substring(0, 300) : String(listener);
      // Check if handler validates origin
      const checksOrigin = /\.origin\b|event\.source|e\.origin/.test(fnStr);

      messageListeners.push({
        hasOriginCheck: checksOrigin,
        handlerPreview: fnStr.substring(0, 200),
        stack: stack.split('\n').slice(1, 4).join(' | ').substring(0, 300),
      });

      _post('POSTMESSAGE_LISTENER', {
        severity: checksOrigin ? 'info' : 'medium',
        description: checksOrigin
          ? 'postMessage listener registered (origin validated)'
          : 'postMessage listener WITHOUT origin check — potential XSS vector',
        handlerPreview: fnStr.substring(0, 200),
        checksOrigin,
      });
    }
    return origAddEventListener.apply(this, arguments);
  };

  // Hook postMessage to log outgoing messages and detect wildcard targetOrigin
  const origPostMessage = window.postMessage;
  window.postMessage = function(message, targetOrigin, transfer) {
    // Skip our own findings channel
    if (message && message.type === '__lonkero_finding__') {
      return origPostMessage.apply(this, arguments);
    }

    const origin = String(targetOrigin || '*');
    if (!seenOrigins.has(origin)) {
      seenOrigins.add(origin);

      if (origin !== '*') {
        _post('POSTMESSAGE_SENT', {
          severity: 'info',
          description: `postMessage sent to ${origin}`,
          targetOrigin: origin,
        });
      }
    }

    return origPostMessage.apply(this, arguments);
  };
})();
