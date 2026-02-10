// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero 403 Bypass Scanner v1.0
 * Tests access control bypass techniques against 403/401 Forbidden responses.
 *
 * Basic techniques:
 * - HTTP method switching (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE)
 * - Path manipulation (trailing slash, double slash, dot segments, semicolons)
 * - URL encoding tricks (%2e, %2f, double encoding, unicode normalization)
 * - Common override headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
 *
 * Advanced techniques:
 * - HTTP verb tunneling (X-HTTP-Method-Override, X-Method-Override)
 * - IP spoofing headers (X-Forwarded-For, X-Real-IP, X-Custom-IP-Authorization, etc.)
 * - Hop-by-hop header abuse
 * - Protocol/version tricks
 * - Referer/Origin spoofing
 * - Path parameter injection and wildcard bypass
 */

(function() {
  'use strict';

  // License verification (same pattern as framework-scanner.js)
  const _wr = document.getElementById('__lk_c');
  const _wc = (_wr && _wr.dataset.v) || window[atob('X19sb25rZXJvS2V5')];
  const _wn = _wr ? _wr.dataset.n : null;
  const _we = _wr ? _wr.dataset.e : null;
  if (!_wc || _wc.charCodeAt(0) !== 76 || _wc.split('-').length !== 5) {
    window.bypassScanner = { scan: () => Promise.reject(new Error('Not available')), deepScan: () => Promise.reject(new Error('Not available')) };
    return;
  }
  let _bpReady = true;

  const _bpGuard = Symbol.for('__lkBP_' + (_wn || ''));
  if (window[_bpGuard]) return;
  window[_bpGuard] = true;

  const findings = [];

  // ============================================
  // CONFIGURATION
  // ============================================

  const BASIC_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  const OVERRIDE_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

  const IP_HEADERS = [
    { header: 'X-Forwarded-For', value: '127.0.0.1' },
    { header: 'X-Real-IP', value: '127.0.0.1' },
    { header: 'X-Originating-IP', value: '127.0.0.1' },
    { header: 'X-Remote-IP', value: '127.0.0.1' },
    { header: 'X-Remote-Addr', value: '127.0.0.1' },
    { header: 'X-Client-IP', value: '127.0.0.1' },
    { header: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
    { header: 'X-Host', value: '127.0.0.1' },
    { header: 'True-Client-IP', value: '127.0.0.1' },
    { header: 'Cluster-Client-IP', value: '127.0.0.1' },
    { header: 'X-ProxyUser-Ip', value: '127.0.0.1' },
    { header: 'CF-Connecting-IP', value: '127.0.0.1' },
    { header: 'Fastly-Client-IP', value: '127.0.0.1' },
    { header: 'X-Forwarded-Host', value: 'localhost' },
  ];

  const METHOD_OVERRIDE_HEADERS = [
    'X-HTTP-Method-Override',
    'X-HTTP-Method',
    'X-Method-Override',
  ];

  // ============================================
  // HELPERS
  // ============================================

  function isBlocked(status) {
    return status === 401 || status === 403 || status === 405;
  }

  function isBypassed(originalStatus, bypassStatus) {
    // Bypass succeeds if we go from 401/403/405 to 200/201/204/301/302/307
    if (!isBlocked(originalStatus)) return false;
    return bypassStatus >= 200 && bypassStatus < 400;
  }

  function parsePath(url) {
    try {
      const u = new URL(url);
      return { origin: u.origin, path: u.pathname, search: u.search, full: u.href };
    } catch {
      return null;
    }
  }

  async function tryRequest(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const resp = await fetch(url, {
        ...options,
        signal: controller.signal,
        credentials: 'include',
        redirect: 'manual',
      });
      clearTimeout(timeout);
      const contentLength = resp.headers.get('content-length');
      const contentType = resp.headers.get('content-type') || '';
      return {
        status: resp.status,
        statusText: resp.statusText,
        contentLength: contentLength ? parseInt(contentLength, 10) : null,
        contentType,
        headers: Object.fromEntries(resp.headers.entries()),
      };
    } catch (e) {
      clearTimeout(timeout);
      return { status: 0, error: e.message };
    }
  }

  // ============================================
  // PATH MUTATION GENERATORS
  // ============================================

  function generateBasicPathMutations(path) {
    const mutations = [];

    // Trailing slash toggle
    if (path.endsWith('/')) {
      mutations.push({ path: path.slice(0, -1), technique: 'Remove trailing slash' });
    } else {
      mutations.push({ path: path + '/', technique: 'Add trailing slash' });
    }

    // Double slash prefix
    mutations.push({ path: '/' + path, technique: 'Double slash prefix //' });

    // Dot segments
    mutations.push({ path: path + '/.',  technique: 'Trailing /.' });
    mutations.push({ path: path + '/..', technique: 'Trailing /..' });
    mutations.push({ path: path + '/./.',  technique: 'Trailing /./.' });

    // Case variations (only if path has alpha characters)
    if (/[a-zA-Z]/.test(path)) {
      mutations.push({ path: path.toUpperCase(), technique: 'Uppercase path' });
      // Toggle first char after each slash
      const toggled = path.replace(/\/([a-z])/g, (m, c) => '/' + c.toUpperCase());
      if (toggled !== path) {
        mutations.push({ path: toggled, technique: 'Mixed case path' });
      }
    }

    // Semicolon path param (Tomcat, Java)
    mutations.push({ path: path + ';', technique: 'Semicolon suffix (path parameter)' });
    mutations.push({ path: path + ';.css', technique: 'Semicolon + static extension' });
    mutations.push({ path: path + ';.js', technique: 'Semicolon + .js extension' });

    // Null byte / encoded
    mutations.push({ path: path + '%00', technique: 'Null byte suffix' });
    mutations.push({ path: path + '%20', technique: 'Encoded space suffix' });
    mutations.push({ path: path + '%09', technique: 'Encoded tab suffix' });

    // Tab and space in path
    mutations.push({ path: path + '\t', technique: 'Tab character suffix' });

    // Hash fragment trick
    mutations.push({ path: path + '#', technique: 'Hash fragment suffix' });
    mutations.push({ path: path + '?', technique: 'Empty query string suffix' });

    return mutations;
  }

  function generateAdvancedPathMutations(path) {
    const mutations = [];

    // URL-encoded slashes
    const encodedSlash = path.replace(/\//g, '%2f');
    mutations.push({ path: encodedSlash, technique: 'URL-encoded slashes (%2f)' });

    // Double URL-encoded slashes
    const doubleEncoded = path.replace(/\//g, '%252f');
    mutations.push({ path: doubleEncoded, technique: 'Double-encoded slashes (%252f)' });

    // URL-encoded dots
    const encodedDots = path.replace(/\./g, '%2e');
    mutations.push({ path: encodedDots, technique: 'URL-encoded dots (%2e)' });

    // Unicode normalization bypass
    mutations.push({ path: path.replace(/\//g, '\u2215'), technique: 'Unicode division slash (\\u2215)' });
    mutations.push({ path: path.replace(/\//g, '\u2044'), technique: 'Unicode fraction slash (\\u2044)' });

    // Path traversal with backtrack
    const segments = path.split('/').filter(Boolean);
    if (segments.length > 0) {
      const last = segments[segments.length - 1];
      mutations.push({ path: path + '/../' + last, technique: 'Path traversal backtrack' });
      mutations.push({ path: '/' + segments.slice(0, -1).join('/') + '/..%2f' + last, technique: 'Encoded traversal backtrack' });
    }

    // Insert random path segment before real path
    mutations.push({ path: '/anything/..' + path, technique: 'Prefix with /anything/..' });
    mutations.push({ path: '/;' + path, technique: 'Semicolon prefix /;path' });

    // Wildcard and glob
    mutations.push({ path: path.replace(/\/([^/]+)$/, '/*'), technique: 'Wildcard last segment' });

    // .json / .html / .xml extension override
    mutations.push({ path: path + '.json', technique: 'Append .json extension' });
    mutations.push({ path: path + '.html', technique: 'Append .html extension' });
    mutations.push({ path: path + '.xml', technique: 'Append .xml extension' });
    mutations.push({ path: path + '.css', technique: 'Append .css extension' });

    // Query param pollution
    mutations.push({ path: path + '?debug=true', technique: 'Debug query parameter' });
    mutations.push({ path: path + '?test=1', technique: 'Test query parameter' });

    // HTTP parameter pollution
    mutations.push({ path: path + '%23', technique: 'Encoded hash (%23)' });
    mutations.push({ path: path + '%3f', technique: 'Encoded question mark (%3f)' });

    return mutations;
  }

  // ============================================
  // SCAN TECHNIQUES
  // ============================================

  /**
   * Test HTTP method switching.
   */
  async function testMethodSwitching(url, originalStatus) {
    const results = [];

    for (const method of BASIC_METHODS) {
      try {
        const resp = await tryRequest(url, { method });
        if (isBypassed(originalStatus, resp.status)) {
          results.push({
            type: 'BYPASS_403_METHOD',
            severity: 'high',
            url,
            technique: `HTTP Method Switch: ${method}`,
            description: `403 bypassed by switching to ${method} method`,
            evidence: `Original: ${originalStatus} → ${method}: ${resp.status}`,
          });
        }
      } catch {}
    }

    return results;
  }

  /**
   * Test path manipulation bypasses.
   */
  async function testPathManipulation(url, originalStatus, advanced) {
    const results = [];
    const parsed = parsePath(url);
    if (!parsed) return results;

    const mutations = advanced
      ? [...generateBasicPathMutations(parsed.path), ...generateAdvancedPathMutations(parsed.path)]
      : generateBasicPathMutations(parsed.path);

    for (const { path: mutatedPath, technique } of mutations) {
      try {
        const testUrl = parsed.origin + mutatedPath + parsed.search;
        const resp = await tryRequest(testUrl);
        if (isBypassed(originalStatus, resp.status)) {
          results.push({
            type: 'BYPASS_403_PATH',
            severity: 'high',
            url: testUrl,
            technique: `Path Manipulation: ${technique}`,
            description: `403 bypassed via path manipulation: ${technique}`,
            evidence: `Original: ${originalStatus} → Modified path: ${resp.status} (${testUrl})`,
          });
        }
      } catch {}
    }

    return results;
  }

  /**
   * Test header-based bypasses (IP spoofing, override headers).
   */
  async function testHeaderBypasses(url, originalStatus) {
    const results = [];

    // IP spoofing headers
    for (const { header, value } of IP_HEADERS) {
      try {
        const resp = await tryRequest(url, {
          headers: { [header]: value },
        });
        if (isBypassed(originalStatus, resp.status)) {
          results.push({
            type: 'BYPASS_403_HEADER',
            severity: 'high',
            url,
            technique: `Header Bypass: ${header}: ${value}`,
            description: `403 bypassed via ${header} header spoofing`,
            evidence: `Original: ${originalStatus} → With ${header}: ${resp.status}`,
          });
        }
      } catch {}
    }

    // X-Original-URL / X-Rewrite-URL (Nginx, IIS)
    const parsed = parsePath(url);
    if (parsed) {
      for (const header of ['X-Original-URL', 'X-Rewrite-URL']) {
        try {
          const resp = await tryRequest(parsed.origin + '/', {
            headers: { [header]: parsed.path },
          });
          if (isBypassed(originalStatus, resp.status)) {
            results.push({
              type: 'BYPASS_403_HEADER',
              severity: 'critical',
              url,
              technique: `URL Override: ${header}`,
              description: `403 bypassed via ${header} header - server routing can be overridden`,
              evidence: `Original: ${originalStatus} → With ${header}: ${parsed.path}: ${resp.status}`,
            });
          }
        } catch {}
      }
    }

    return results;
  }

  /**
   * Test HTTP verb tunneling (method override headers).
   */
  async function testVerbTunneling(url, originalStatus) {
    const results = [];

    for (const overrideHeader of METHOD_OVERRIDE_HEADERS) {
      for (const method of OVERRIDE_METHODS) {
        try {
          const resp = await tryRequest(url, {
            method: 'POST',
            headers: {
              [overrideHeader]: method,
              'Content-Length': '0',
            },
          });
          if (isBypassed(originalStatus, resp.status)) {
            results.push({
              type: 'BYPASS_403_VERB_TUNNEL',
              severity: 'high',
              url,
              technique: `Verb Tunneling: POST + ${overrideHeader}: ${method}`,
              description: `403 bypassed via HTTP method override header`,
              evidence: `Original: ${originalStatus} → POST with ${overrideHeader}: ${method}: ${resp.status}`,
            });
          }
        } catch {}
      }
    }

    return results;
  }

  /**
   * Test Referer/Origin header spoofing.
   */
  async function testRefererOriginBypass(url, originalStatus) {
    const results = [];
    const parsed = parsePath(url);
    if (!parsed) return results;

    const spoofValues = [
      parsed.origin,
      parsed.origin + '/admin',
      parsed.origin + '/internal',
      'http://localhost',
      'http://127.0.0.1',
    ];

    for (const ref of spoofValues) {
      try {
        const resp = await tryRequest(url, {
          headers: { 'Referer': ref },
        });
        if (isBypassed(originalStatus, resp.status)) {
          results.push({
            type: 'BYPASS_403_REFERER',
            severity: 'medium',
            url,
            technique: `Referer Spoofing: ${ref}`,
            description: `403 bypassed via Referer header spoofing`,
            evidence: `Original: ${originalStatus} → With Referer ${ref}: ${resp.status}`,
          });
          break; // One is enough
        }
      } catch {}
    }

    return results;
  }

  /**
   * Test Content-Type manipulation (may bypass WAF/middleware).
   */
  async function testContentTypeBypass(url, originalStatus) {
    const results = [];

    const contentTypes = [
      'application/json',
      'application/xml',
      'application/x-www-form-urlencoded',
      'text/plain',
      'multipart/form-data',
    ];

    for (const ct of contentTypes) {
      try {
        const resp = await tryRequest(url, {
          method: 'POST',
          headers: { 'Content-Type': ct },
          body: '',
        });
        if (isBypassed(originalStatus, resp.status)) {
          results.push({
            type: 'BYPASS_403_CONTENT_TYPE',
            severity: 'medium',
            url,
            technique: `Content-Type: ${ct}`,
            description: `403 bypassed via Content-Type manipulation`,
            evidence: `Original: ${originalStatus} → POST with Content-Type ${ct}: ${resp.status}`,
          });
          break;
        }
      } catch {}
    }

    return results;
  }

  // ============================================
  // MAIN SCAN FUNCTIONS
  // ============================================

  /**
   * Basic scan - quick test with most common techniques.
   * Tests: method switching, basic path mutations, key headers.
   */
  async function scan(targetUrl) {
    const url = targetUrl || location.href;
    console.log(`[403 Bypass Scanner] Starting basic scan on ${url}...`);

    // First, confirm the URL is actually blocked
    const baseline = await tryRequest(url);
    if (!isBlocked(baseline.status)) {
      console.log(`[403 Bypass Scanner] URL returns ${baseline.status}, not blocked. Skipping.`);
      return {
        findings: [],
        url,
        originalStatus: baseline.status,
        message: `URL is not blocked (status: ${baseline.status}). 403 bypass testing requires a 401/403/405 response.`,
      };
    }

    console.log(`[403 Bypass Scanner] Confirmed ${baseline.status} response. Testing bypasses...`);
    const allFindings = [];

    // Run basic techniques
    const [methods, paths, headers] = await Promise.all([
      testMethodSwitching(url, baseline.status),
      testPathManipulation(url, baseline.status, false),
      testHeaderBypasses(url, baseline.status),
    ]);

    allFindings.push(...methods, ...paths, ...headers);

    // Report findings
    for (const finding of allFindings) {
      reportFinding(finding);
    }

    const report = buildReport(url, baseline.status, allFindings);
    console.log(`[403 Bypass Scanner] Basic scan complete. Found ${allFindings.length} bypasses.`);

    window.postMessage({
      type: '__lonkero_bypass_scan_complete__',
      _n: _wn, _ch: _we,
      ...report,
    }, '*');

    return report;
  }

  /**
   * Deep scan - comprehensive test with all techniques.
   * Tests: everything in basic + verb tunneling, referer spoofing,
   *        content-type tricks, advanced path mutations.
   */
  async function deepScan(targetUrl) {
    const url = targetUrl || location.href;
    console.log(`[403 Bypass Scanner] Starting deep scan on ${url}...`);

    // Confirm blocked
    const baseline = await tryRequest(url);
    if (!isBlocked(baseline.status)) {
      console.log(`[403 Bypass Scanner] URL returns ${baseline.status}, not blocked. Skipping.`);
      return {
        findings: [],
        url,
        originalStatus: baseline.status,
        message: `URL is not blocked (status: ${baseline.status}). 403 bypass testing requires a 401/403/405 response.`,
      };
    }

    console.log(`[403 Bypass Scanner] Confirmed ${baseline.status} response. Running deep bypass tests...`);
    const allFindings = [];

    // Run all techniques (some in parallel, some sequential to avoid rate limiting)
    const [methods, paths, headers] = await Promise.all([
      testMethodSwitching(url, baseline.status),
      testPathManipulation(url, baseline.status, true),
      testHeaderBypasses(url, baseline.status),
    ]);
    allFindings.push(...methods, ...paths, ...headers);

    // Sequential advanced techniques
    const verbResults = await testVerbTunneling(url, baseline.status);
    allFindings.push(...verbResults);

    const refererResults = await testRefererOriginBypass(url, baseline.status);
    allFindings.push(...refererResults);

    const ctResults = await testContentTypeBypass(url, baseline.status);
    allFindings.push(...ctResults);

    // Report findings
    for (const finding of allFindings) {
      reportFinding(finding);
    }

    const report = buildReport(url, baseline.status, allFindings);
    console.log(`[403 Bypass Scanner] Deep scan complete. Found ${allFindings.length} bypasses.`);

    window.postMessage({
      type: '__lonkero_bypass_scan_complete__',
      _n: _wn, _ch: _we,
      ...report,
    }, '*');

    return report;
  }

  /**
   * Scan multiple URLs (e.g., discovered endpoints that return 403).
   */
  async function scanMultiple(urls) {
    console.log(`[403 Bypass Scanner] Batch scanning ${urls.length} URLs...`);
    const allResults = [];

    for (const url of urls) {
      const result = await scan(url);
      allResults.push(result);
    }

    const totalFindings = allResults.reduce((sum, r) => sum + r.findings.length, 0);
    console.log(`[403 Bypass Scanner] Batch scan complete. ${totalFindings} total bypasses across ${urls.length} URLs.`);
    return allResults;
  }

  // ============================================
  // REPORTING
  // ============================================

  function buildReport(url, originalStatus, scanFindings) {
    return {
      findings: scanFindings,
      url,
      originalStatus,
      findingCount: scanFindings.length,
      criticalCount: scanFindings.filter(f => f.severity === 'critical').length,
      highCount: scanFindings.filter(f => f.severity === 'high').length,
      mediumCount: scanFindings.filter(f => f.severity === 'medium').length,
      techniques: {
        method: scanFindings.filter(f => f.type === 'BYPASS_403_METHOD').length,
        path: scanFindings.filter(f => f.type === 'BYPASS_403_PATH').length,
        header: scanFindings.filter(f => f.type === 'BYPASS_403_HEADER').length,
        verbTunnel: scanFindings.filter(f => f.type === 'BYPASS_403_VERB_TUNNEL').length,
        referer: scanFindings.filter(f => f.type === 'BYPASS_403_REFERER').length,
        contentType: scanFindings.filter(f => f.type === 'BYPASS_403_CONTENT_TYPE').length,
      },
    };
  }

  function reportFinding(finding) {
    if (!_bpReady || !_wc) return;
    window.postMessage({
      type: '__lonkero_bypass_finding__',
      _n: _wn, _ch: _we,
      finding,
    }, '*');
    findings.push(finding);

    const severity = finding.severity?.toUpperCase() || 'INFO';
    console.log(`[403 Bypass Scanner] ${severity}: ${finding.technique}`, finding);
  }

  // ============================================
  // PUBLIC API
  // ============================================

  if (!window.bypassScanner) Object.defineProperty(window, 'bypassScanner', { value: {
    scan,
    deepScan,
    scanMultiple,
    getFindings: () => findings,
    clearFindings: () => { findings.length = 0; },
  }, configurable: false, enumerable: false });

  // Listen for scan requests (nonce+channel validated)
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!_we || event.data?._ch !== _we || event.data?._n !== _wn) return;
    if (event.data?.type === '__lonkero_run_bypass_scan__') {
      scan(event.data.url);
    }
    if (event.data?.type === '__lonkero_run_bypass_deep_scan__') {
      deepScan(event.data.url);
    }
  });

  console.log('[Lonkero] 403 Bypass Scanner v1.0 loaded. Use bypassScanner.scan() or bypassScanner.deepScan().');
})();
