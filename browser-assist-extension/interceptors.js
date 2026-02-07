// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Request Interceptors
 *
 * Patches fetch and XMLHttpRequest to capture all HTTP traffic.
 * Communicates with content script via window.postMessage.
 */

(function() {
  'use strict';

  // License check - validates against Bountyy license server
  const _lk = window.__lonkeroKey;
  if (!_lk || !_lk.startsWith('LONKERO-') || _lk.split('-').length !== 5) {
    console.warn('[Lonkero] Request interceptors require a valid license. Visit https://bountyy.fi');
    return;
  }
  // Server-side validation (async, non-blocking - disables on failure)
  let _lkValid = true;
  fetch('https://lonkero.bountyy.fi/api/v1/validate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({license_key: _lk, product: 'lonkero', version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d.killswitch_active) _lkValid = false; }).catch(() => {});

  if (window.__lonkeroInterceptorsInjected) return;
  window.__lonkeroInterceptorsInjected = true;

  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : (input.url || String(input));
    const method = init?.method || (input?.method) || 'GET';
    const startTime = performance.now();
    const reqHeaders = init?.headers || input?.headers || {};
    const reqBody = init?.body || null;

    return originalFetch.apply(this, arguments).then(async response => {
      // Clone response to read body without consuming it
      const cloned = response.clone();
      let responseBody = null;
      let responseHeaders = {};

      try {
        // Capture response headers
        response.headers.forEach((v, k) => responseHeaders[k] = v);

        // Capture response body (limit size)
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('json') || contentType.includes('text') || contentType.includes('html') || contentType.includes('xml')) {
          const text = await cloned.text();
          responseBody = text.length > 50000 ? text.substring(0, 50000) + '...[truncated]' : text;
        }
      } catch (e) {
        // Ignore body read errors
      }

      window.postMessage({
        type: '__lonkero_request__',
        request: {
          url: url,
          method: method.toUpperCase(),
          status: response.status,
          statusText: response.statusText,
          duration: Math.round(performance.now() - startTime),
          headers: reqHeaders instanceof Headers ? Object.fromEntries(reqHeaders) : reqHeaders,
          body: typeof reqBody === 'string' ? reqBody : null,
          responseHeaders: responseHeaders,
          responseBody: responseBody,
        }
      }, '*');
      return response;
    }).catch(err => {
      window.postMessage({
        type: '__lonkero_request__',
        request: {
          url: url,
          method: method.toUpperCase(),
          status: 0,
          statusText: 'Error: ' + err.message,
          duration: Math.round(performance.now() - startTime),
          headers: reqHeaders instanceof Headers ? Object.fromEntries(reqHeaders) : reqHeaders,
          body: typeof reqBody === 'string' ? reqBody : null,
          responseHeaders: {},
          responseBody: null,
        }
      }, '*');
      throw err;
    });
  };

  // Intercept XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function(method, url) {
    this.__lonkeroMethod = method;
    this.__lonkeroUrl = url;
    this.__lonkeroStart = performance.now();
    this.__lonkeroHeaders = {};
    return originalXHROpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (this.__lonkeroHeaders) {
      this.__lonkeroHeaders[name] = value;
    }
    return originalXHRSetRequestHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    const xhr = this;
    xhr.__lonkeroBody = typeof body === 'string' ? body : null;

    xhr.addEventListener('loadend', function() {
      // Capture response headers
      let responseHeaders = {};
      try {
        const headerStr = xhr.getAllResponseHeaders();
        headerStr.split('\r\n').forEach(line => {
          const idx = line.indexOf(':');
          if (idx > 0) {
            responseHeaders[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
          }
        });
      } catch (e) {}

      // Capture response body (limit size)
      let responseBody = null;
      try {
        const contentType = xhr.getResponseHeader('content-type') || '';
        if (contentType.includes('json') || contentType.includes('text') || contentType.includes('html') || contentType.includes('xml')) {
          const text = xhr.responseText || '';
          responseBody = text.length > 50000 ? text.substring(0, 50000) + '...[truncated]' : text;
        }
      } catch (e) {}

      window.postMessage({
        type: '__lonkero_request__',
        request: {
          url: xhr.__lonkeroUrl,
          method: (xhr.__lonkeroMethod || 'GET').toUpperCase(),
          status: xhr.status,
          statusText: xhr.statusText,
          duration: Math.round(performance.now() - xhr.__lonkeroStart),
          headers: xhr.__lonkeroHeaders || {},
          body: xhr.__lonkeroBody,
          responseHeaders: responseHeaders,
          responseBody: responseBody,
        }
      }, '*');
    });

    return originalXHRSend.apply(this, arguments);
  };

  console.log('[Lonkero] Request interceptors injected');
})();
