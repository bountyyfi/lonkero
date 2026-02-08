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

  if (window.__lkDH) return;
  window.__lkDH = true;

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
          _post('DOM_XSS_POTENTIAL', {
            sink: 'innerHTML',
            element: this.tagName,
            valuePreview: v.substring(0, 200),
            severity: 'high',
          });
        }
        return origInnerHTML.set.call(this, value);
      },
      get: origInnerHTML.get,
      configurable: true,
    });
  }

  // Monitor document.write
  const origWrite = document.write;
  document.write = function(content) {
    const v = String(content);
    if (/<script|javascript:|on\w+=/i.test(v)) {
      _post('DOM_XSS_SINK', {
        sink: 'document.write',
        valuePreview: v.substring(0, 200),
        severity: 'critical',
      });
    }
    return origWrite.apply(this, arguments);
  };

  // Monitor eval
  const origEval = window.eval;
  Object.defineProperty(window, 'eval', { value: function(code) {
    _post('DANGEROUS_EVAL', {
      codePreview: String(code).substring(0, 200),
      severity: 'high',
    });
    return origEval.apply(this, arguments);
  }, configurable: false, enumerable: false });
})();
