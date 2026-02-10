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

  // Rate limiters — cap findings per type to prevent message flood on heavy sites (google.com etc.)
  const _findingCounts = {};
  const _MAX_FINDINGS_PER_TYPE = 10;

  function _post(type, data) {
    if (!_he) return;
    // Rate limit: stop posting after N findings of the same type
    _findingCounts[type] = (_findingCounts[type] || 0) + 1;
    if (_findingCounts[type] > _MAX_FINDINGS_PER_TYPE) return;
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
        // Skip all checks if rate limit reached (performance)
        if ((_findingCounts['DOM_XSS_POTENTIAL'] || 0) < _MAX_FINDINGS_PER_TYPE) {
          const v = String(value);
          if (/<script|javascript:|on\w+=/i.test(v)) {
            // Skip known-benign: analytics/marketing SDKs that inject scripts via innerHTML
            if (!/text\/gtmscript|google_tag_manager|googletag|gtag|SnitchObject|Snitcher|hotjar|_hj[A-Z]|clarity\.|mouseflow|hubspot|hs-scripts|drift\.com|intercom|pendo|fullstory|heapanalytics|luckyorange|segment\.com|amplitude|cookieinformation|CookieInformation|cookie.?consent|onetrust|cookiebot|Usercentrics|didomi|quantcast/.test(v)) {
              _post('DOM_XSS_POTENTIAL', {
                sink: 'innerHTML',
                element: this.tagName,
                valuePreview: v.substring(0, 200),
                severity: 'high',
              });
            }
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
    if ((_findingCounts['DOM_XSS_SINK'] || 0) < _MAX_FINDINGS_PER_TYPE) {
      const v = String(content);
      if (/<script|javascript:|on\w+=/i.test(v)) {
        _post('DOM_XSS_SINK', {
          sink: 'document.write',
          valuePreview: v.substring(0, 200),
          severity: 'critical',
        });
      }
    }
    return origWrite.apply(this, arguments);
  }, configurable: false, writable: false });

  // Monitor eval (filter known-benign callers like GTM, ad tags, analytics)
  const origEval = window.eval;

  // Pre-compile benign SDK regex (tested on first 300 chars of eval code)
  const _benignSDKRe = /google_tag_manager|googletag\.|googleads|google_ad|gtag|adsbygoogle|exponea|bloomreach|hotjar|_hj|clarity\.|mouseflow|tealium|segment\.|optimizely|abtasty|kameleoon|cookiebot|onetrust|didomi|quantcast|facebook\.net|fbq|fbevents|connect\.facebook|twitter\.com\/oct|snap\.licdn|pinterest\.com\/tag|tiktok\.com\/i18n|CookieInformation|CookieConsent|cookie_?consent|__cmp|__tcfapi|Usercentrics|DYO\.|DynamicYield|_vwo_|VWO\.|Qubit|convert\.com/;

  Object.defineProperty(window, 'eval', { value: function(code) {
    // Fast path: skip all checks once rate limit is reached
    if ((_findingCounts['DANGEROUS_EVAL'] || 0) >= _MAX_FINDINGS_PER_TYPE) {
      return origEval.apply(this, arguments);
    }

    const s = String(code);

    // Fast path: very short evals are almost always benign (property checks, simple expressions)
    if (s.length < 60) {
      return origEval.apply(this, arguments);
    }

    const preview = s.substring(0, 300);

    // Skip known-benign: third-party analytics, marketing, and tag managers
    if (_benignSDKRe.test(preview)) {
      return origEval.apply(this, arguments);
    }

    // Skip simple patterns (only compute stripped if we passed SDK check)
    const stripped = preview.replace(/\s/g, '');
    const benignPattern = /^\(function\(\)\{return\s*(window\.\w+\?|Math\.|"|\d|sessionStorage|localStorage)/.test(stripped)
      || /^\(function\(\)\{(var\s+\w+=)?.*Math\.(random|floor|ceil|round|abs)\b/.test(stripped)
      || /classList\.contains|matchMedia|prefers-color-scheme|getComputedStyle|getBoundingClientRect/.test(stripped)
      || /sessionStorage\.getItem|localStorage\.getItem/.test(stripped)
      || /^DYO\.|^Kameleoon|^VWO\.|^Optimizely|^AB\.|^_vwo_|^convert\.|^Qubit/.test(stripped);

    if (!benignPattern) {
      _post('DANGEROUS_EVAL', {
        codePreview: preview.substring(0, 200),
        severity: 'high',
      });
    }

    return origEval.apply(this, arguments);
  }, configurable: false, enumerable: false });
})();
