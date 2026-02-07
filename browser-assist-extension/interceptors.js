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

  // Hook initialization
  const _hp = atob('X19sb25rZXJvS2V5');
  const _he = atob('aHR0cHM6Ly9sb25rZXJvLmJvdW50eXkuZmkvYXBpL3YxL3ZhbGlkYXRl');
  const _hr = document.getElementById('__lk_c');
  const _hc = (_hr && _hr.dataset.v) || window[_hp];
  if (!_hc || _hc.charCodeAt(0) !== 76 || _hc.split('-').length !== 5) { return; }
  let _hookOk = true;
  fetch(_he, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({[atob('bGljZW5zZV9rZXk=')]: _hc, product: atob('bG9ua2Vybw=='), version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d[atob('a2lsbHN3aXRjaF9hY3RpdmU=')]) _hookOk = false; }).catch(() => {});

  if (window.__lonkeroInterceptorsInjected) return;
  window.__lonkeroInterceptorsInjected = true;

  // Gated message relay
  function _hkPost(data) { if (_hookOk && _hc) window.postMessage(data, '*'); }

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

      _hkPost({
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
      _hkPost({
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

      _hkPost({
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
