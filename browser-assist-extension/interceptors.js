/**
 * Lonkero Request Interceptors
 *
 * Patches fetch and XMLHttpRequest to capture all HTTP traffic.
 * Communicates with content script via window.postMessage.
 */

(function() {
  'use strict';

  if (window.__lonkeroInterceptorsInjected) return;
  window.__lonkeroInterceptorsInjected = true;

  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : (input.url || String(input));
    const method = init?.method || (input?.method) || 'GET';
    const startTime = performance.now();
    const headers = init?.headers || input?.headers || {};
    const body = init?.body || null;

    return originalFetch.apply(this, arguments).then(response => {
      window.postMessage({
        type: '__lonkero_request__',
        request: {
          url: url,
          method: method.toUpperCase(),
          status: response.status,
          statusText: response.statusText,
          duration: Math.round(performance.now() - startTime),
          headers: headers instanceof Headers ? Object.fromEntries(headers) : headers,
          body: typeof body === 'string' ? body : null,
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
          headers: headers instanceof Headers ? Object.fromEntries(headers) : headers,
          body: typeof body === 'string' ? body : null,
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
        }
      }, '*');
    });

    return originalXHRSend.apply(this, arguments);
  };

  console.log('[Lonkero] Request interceptors injected');
})();
