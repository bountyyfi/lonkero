/**
 * Lonkero Browser-Assist Mode - Background Service Worker
 *
 * Advanced security scanning with:
 * - Real-time vulnerability detection (DOM XSS, Prototype Pollution)
 * - Session capture and authenticated scanning
 * - API endpoint discovery
 * - Request interception and replay
 * - Lonkero CLI integration
 */

const LONKERO_WS_URL = 'ws://127.0.0.1:9340/parasite';
let ws = null;
let reconnectInterval = null;

// ============================================================
// STATE MANAGEMENT
// ============================================================

let state = {
  connected: false,
  monitoring: false,
  paused: false,
  stopped: false,
  scope: [],
  authorization: null,

  // Statistics
  requestsProxied: 0,
  requestsBlocked: 0,
  errors: 0,

  // Discoveries
  findings: [],
  endpoints: [],
  secrets: [],
  sessions: new Map(), // Per-origin session data

  // Request capture
  capturedRequests: [],
  maxCapturedRequests: 500,

  // Page analysis
  pageAnalysis: new Map(),

  // Audit log
  auditLog: [],
  lastRequest: null,
  sessionStart: null,
};

// ============================================================
// WEBSOCKET CONNECTION (Lonkero CLI)
// ============================================================

function connect() {
  if (ws && ws.readyState === WebSocket.OPEN) return;

  try {
    ws = new WebSocket(LONKERO_WS_URL);

    ws.onopen = () => {
      console.log('[Lonkero] Connected to scanner');
      state.connected = true;
      state.sessionStart = new Date().toISOString();

      if (reconnectInterval) {
        clearInterval(reconnectInterval);
        reconnectInterval = null;
      }

      // Send handshake with capabilities
      ws.send(JSON.stringify({
        type: 'handshake',
        version: '3.0.0',
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        mode: 'browser-assist',
        capabilities: [
          'authenticated-scanning',
          'dom-xss-detection',
          'prototype-pollution',
          'secret-scanning',
          'endpoint-discovery',
          'request-replay',
        ],
      }));

      audit('CONNECTED', '', '', 'Session started');
    };

    ws.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);
        await handleMessage(msg);
      } catch (e) {
        console.error('[Lonkero] Message parse error:', e);
        state.errors++;
      }
    };

    ws.onclose = () => {
      console.log('[Lonkero] Disconnected');
      state.connected = false;
      ws = null;
      audit('DISCONNECTED', '', '', 'Session ended');

      if (!state.stopped && !reconnectInterval) {
        reconnectInterval = setInterval(() => connect(), 3000);
      }
    };

    ws.onerror = (error) => {
      console.error('[Lonkero] WebSocket error:', error);
      state.errors++;
    };

  } catch (e) {
    console.error('[Lonkero] Connection failed:', e);
    state.errors++;
  }
}

// ============================================================
// MESSAGE HANDLING (from Lonkero CLI)
// ============================================================

async function handleMessage(msg) {
  switch (msg.type) {
    case 'request':
      await handleProxyRequest(msg);
      break;

    case 'ping':
      ws.send(JSON.stringify({ type: 'pong', id: msg.id }));
      break;

    case 'setScope':
      state.scope = msg.patterns || [];
      state.authorization = msg.authorization || null;
      audit('SCOPE_SET', '', '', `Scope: ${state.scope.join(', ')}`);
      break;

    case 'pause':
      state.paused = true;
      audit('PAUSED', '', '', 'Scanning paused');
      break;

    case 'resume':
      state.paused = false;
      audit('RESUMED', '', '', 'Scanning resumed');
      break;

    case 'stop':
      state.stopped = true;
      audit('STOPPED', '', '', 'Scanning stopped');
      break;

    case 'getFindings':
      ws.send(JSON.stringify({
        type: 'findings',
        id: msg.id,
        findings: state.findings,
        endpoints: state.endpoints,
        secrets: state.secrets,
      }));
      break;

    case 'getEndpoints':
      ws.send(JSON.stringify({
        type: 'endpoints',
        id: msg.id,
        endpoints: state.endpoints,
      }));
      break;

    case 'replay':
      await handleReplayRequest(msg);
      break;

    // ============================================================
    // REAL-TIME INTELLIGENCE SHARING (CLI → Extension)
    // ============================================================

    case 'finding':
      // CLI discovered a vulnerability - add to findings and highlight
      const finding = msg.finding;
      state.findings.push(finding);

      // Notify devtools panel
      chrome.runtime.sendMessage({
        type: 'newFinding',
        finding: finding
      }).catch(() => {});

      // Highlight in active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'highlight_finding',
            finding: finding
          }).catch(() => {});
        }
      });

      audit('FINDING', finding.url || '', '', `${finding.severity}: ${finding.vuln_type || finding.type}`);
      break;

    case 'tech_detected':
      // CLI detected technologies
      console.log('[Lonkero] Tech detected:', msg.technologies);
      chrome.runtime.sendMessage({
        type: 'cliMessage',
        data: msg
      }).catch(() => {});
      break;

    case 'param_risk':
      // CLI sending parameter risk scores for highlighting
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'highlight_params',
            parameters: msg.parameters
          }).catch(() => {});
        }
      });
      break;

    case 'scan_progress':
      // CLI sending scan progress update
      chrome.runtime.sendMessage({
        type: 'scanProgress',
        percent: msg.percent,
        scanner: msg.scanner,
        phase: msg.phase,
        requests: msg.requests,
        findings: msg.findings
      }).catch(() => {});

      // Update content script indicator
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'scan_progress',
            scanner: msg.scanner,
            percent: msg.percent
          }).catch(() => {});
        }
      });
      break;

    case 'scan_started':
      state.scanning = true;
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'scan_started',
            scanner: msg.scanner
          }).catch(() => {});
        }
      });
      break;

    case 'scan_complete':
      state.scanning = false;
      chrome.runtime.sendMessage({ type: 'scanComplete' }).catch(() => {});
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'scan_complete'
          }).catch(() => {});
        }
      });
      audit('SCAN_COMPLETE', '', '', `Found ${state.findings.length} vulnerabilities`);
      break;

    case 'get_page_context':
      // CLI requesting page context from content script
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'get_page_context'
          }, (context) => {
            if (ws?.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({
                type: 'page_context',
                id: msg.id,
                context: context
              }));
            }
          });
        }
      });
      break;

    case 'clear_highlights':
      // CLI requesting to clear all highlights
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, { type: 'clear_highlights' }).catch(() => {});
        });
      });
      break;

    default:
      console.warn('[Lonkero] Unknown message:', msg.type);
  }
}

// ============================================================
// REQUEST PROXYING (Authenticated)
// ============================================================

async function handleProxyRequest(msg) {
  const { id, url, method, headers, body, timeout, useCredentials } = msg;
  const startTime = performance.now();

  if (state.paused) {
    ws.send(JSON.stringify({ type: 'error', id, error: 'paused' }));
    return;
  }

  if (state.stopped) {
    ws.send(JSON.stringify({ type: 'error', id, error: 'stopped' }));
    return;
  }

  // Scope enforcement
  if (!isInScope(url)) {
    state.requestsBlocked++;
    audit('BLOCKED', url, method, 'Out of scope');
    ws.send(JSON.stringify({
      type: 'error', id, error: 'out_of_scope',
      message: `Not in scope: ${state.scope.join(', ')}`
    }));
    return;
  }

  audit('REQUEST', url, method);

  try {
    const fetchOptions = {
      method: method || 'GET',
      headers: headers || {},
      credentials: useCredentials !== false ? 'include' : 'omit',
      redirect: 'follow',
      referrerPolicy: 'same-origin',
    };

    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      fetchOptions.body = body;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout || 30000);
    fetchOptions.signal = controller.signal;

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const responseBody = await response.text();
    const responseHeaders = {};
    response.headers.forEach((v, k) => responseHeaders[k.toLowerCase()] = v);

    const duration = Math.round(performance.now() - startTime);

    ws.send(JSON.stringify({
      type: 'response', id,
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
      url: response.url,
      duration,
    }));

    state.requestsProxied++;
    state.lastRequest = { url, status: response.status, duration, timestamp: Date.now() };
    audit('RESPONSE', url, method, `${response.status} (${duration}ms)`);

  } catch (error) {
    const duration = Math.round(performance.now() - startTime);
    ws.send(JSON.stringify({
      type: 'error', id,
      error: error.name,
      message: error.message,
      duration,
    }));
    state.errors++;
    audit('ERROR', url, method, error.message);
  }
}

// ============================================================
// SCOPE CHECKING
// ============================================================

function isInScope(url) {
  if (!state.scope || state.scope.length === 0) return false;

  try {
    const parsed = new URL(url);
    const host = parsed.hostname;

    for (const pattern of state.scope) {
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(1);
        const root = pattern.slice(2);
        if (host.endsWith(suffix) || host === root) return true;
      } else {
        if (host === pattern) return true;
      }
    }
  } catch (e) {}

  return false;
}

// ============================================================
// AUDIT LOGGING
// ============================================================

function audit(action, url, method, details = null) {
  const entry = {
    timestamp: new Date().toISOString(),
    action, url, method, details,
  };
  state.auditLog.push(entry);

  if (state.auditLog.length > 1000) {
    state.auditLog = state.auditLog.slice(-1000);
  }

  chrome.storage.local.set({ auditLog: state.auditLog });
}

// ============================================================
// CONTENT SCRIPT MESSAGE HANDLING
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    // State queries
    case 'getState':
      sendResponse({
        ...state,
        sessions: undefined, // Don't serialize Map
        pageAnalysis: undefined,
        findingsCount: state.findings.length,
        endpointsCount: state.endpoints.length,
        secretsCount: state.secrets.length,
      });
      break;

    // Control commands
    case 'startMonitoring':
      state.monitoring = true;
      sendResponse({ ok: true });
      break;

    case 'stopMonitoring':
      state.monitoring = false;
      sendResponse({ ok: true });
      break;

    case 'pause':
      state.paused = true;
      audit('PAUSED', '', '', 'By user');
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'userPaused' }));
      }
      sendResponse({ ok: true });
      break;

    case 'resume':
      state.paused = false;
      audit('RESUMED', '', '', 'By user');
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'userResumed' }));
      }
      sendResponse({ ok: true });
      break;

    case 'stop':
      state.stopped = true;
      audit('STOPPED', '', '', 'By user');
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'userStopped' }));
        ws.close();
      }
      if (reconnectInterval) {
        clearInterval(reconnectInterval);
        reconnectInterval = null;
      }
      sendResponse({ ok: true });
      break;

    case 'reconnect':
      state.stopped = false;
      connect();
      sendResponse({ ok: true });
      break;

    // Findings from content script
    case 'finding':
      const finding = {
        ...message.finding,
        id: state.findings.length + 1,
        tabId: sender.tab?.id,
        tabUrl: sender.tab?.url,
      };

      // Deduplicate findings by type + url + evidence
      const findingKey = `${finding.type}:${finding.url || finding.tabUrl}:${finding.evidence || finding.value || ''}`;
      const isDuplicate = state.findings.some(f =>
        `${f.type}:${f.url || f.tabUrl}:${f.evidence || f.value || ''}` === findingKey
      );

      if (!isDuplicate) {
        state.findings.push(finding);

        // Forward to CLI if connected
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'finding', finding }));
        }
      }
      sendResponse({ ok: true });
      break;

    // Endpoint discovery
    case 'endpointDiscovered':
      const endpoint = message.endpoint;
      const key = `${endpoint.method} ${endpoint.path}`;
      if (!state.endpoints.find(e => `${e.method} ${e.path}` === key)) {
        state.endpoints.push(endpoint);

        if (ws?.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'endpoint', endpoint }));
        }
      }
      sendResponse({ ok: true });
      break;

    // Request captured from content script - always capture, monitoring just controls display
    case 'requestCaptured':
      const captured = {
        ...message.request,
        id: state.capturedRequests.length + 1,
        timestamp: Date.now(),
        tabId: sender.tab?.id,
        tabUrl: sender.tab?.url,
      };
      state.capturedRequests.push(captured);
      // Keep only last N requests
      if (state.capturedRequests.length > state.maxCapturedRequests) {
        state.capturedRequests = state.capturedRequests.slice(-state.maxCapturedRequests);
      }
      state.requestsProxied++;
      sendResponse({ ok: true });
      break;

    // Page analysis
    case 'pageAnalysis':
      state.pageAnalysis.set(message.data.url, message.data);

      // Store session data per origin
      try {
        const origin = new URL(message.data.url).origin;
        state.sessions.set(origin, message.data.sessionData);
      } catch (e) {}

      sendResponse({ ok: true });
      break;

    // Get discoveries
    case 'getFindings':
      sendResponse(state.findings);
      break;

    case 'getEndpoints':
      sendResponse(state.endpoints);
      break;

    case 'getSecrets':
      sendResponse(state.secrets);
      break;

    case 'getCapturedRequests':
      sendResponse(state.capturedRequests);
      break;

    // Request replay
    case 'replayRequest':
      handleReplayFromPopup(message.request).then(sendResponse);
      return true; // Async response

    // Export
    case 'exportAuditLog':
      sendResponse({ log: JSON.stringify(state.auditLog, null, 2) });
      break;

    case 'exportFindings':
      sendResponse({
        findings: state.findings,
        endpoints: state.endpoints,
        secrets: state.secrets,
      });
      break;

    // Deep scan trigger
    case 'triggerDeepScan':
      triggerDeepScan().then(sendResponse);
      return true;

    // ============================================================
    // BIDIRECTIONAL SCAN CONTROL (DevTools Panel → CLI)
    // ============================================================

    case 'startScan':
      if (ws?.readyState === WebSocket.OPEN) {
        state.scope = message.scope || [];
        ws.send(JSON.stringify({
          type: 'startScan',
          scope: message.scope,
          options: message.options,
          targets: message.targets,
        }));
        audit('SCAN_STARTED', '', '', `Scope: ${state.scope.join(', ')}`);
        sendResponse({ ok: true });
      } else {
        sendResponse({ error: 'Not connected to CLI' });
      }
      break;

    case 'pauseScan':
      if (ws?.readyState === WebSocket.OPEN) {
        state.paused = true;
        ws.send(JSON.stringify({ type: 'pauseScan' }));
        audit('PAUSED', '', '', 'By DevTools panel');
        sendResponse({ ok: true });
      } else {
        sendResponse({ error: 'Not connected to CLI' });
      }
      break;

    case 'resumeScan':
      if (ws?.readyState === WebSocket.OPEN) {
        state.paused = false;
        ws.send(JSON.stringify({ type: 'resumeScan' }));
        audit('RESUMED', '', '', 'By DevTools panel');
        sendResponse({ ok: true });
      } else {
        sendResponse({ error: 'Not connected to CLI' });
      }
      break;

    case 'stopScan':
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'stopScan' }));
        audit('STOPPED', '', '', 'By DevTools panel');
        sendResponse({ ok: true });
      } else {
        sendResponse({ error: 'Not connected to CLI' });
      }
      break;

    case 'scanRequest':
      // Send single request to CLI for scanning
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'scanRequest',
          request: message.request,
        }));
        sendResponse({ ok: true });
      } else {
        sendResponse({ error: 'Not connected to CLI' });
      }
      break;

    case 'intruderAttack':
      // Send intruder attack request to CLI
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'intruderAttack',
          template: message.template,
          payloads: message.payloads,
        }));
        sendResponse({ ok: true });
      } else {
        // Run locally if CLI not connected
        runLocalIntruderAttack(message.template, message.payloads).then(sendResponse);
        return true;
      }
      break;

    case 'repeaterRequest':
      // Send repeater request
      handleReplayFromPopup(message.request).then(sendResponse);
      return true;

    case 'clearRequests':
      state.capturedRequests = [];
      sendResponse({ ok: true });
      break;

    case 'disconnect':
      if (ws) {
        state.stopped = true;
        ws.close();
      }
      sendResponse({ ok: true });
      break;

    // Clear data
    case 'clearData':
      state.findings = [];
      state.endpoints = [];
      state.secrets = [];
      state.capturedRequests = [];
      state.auditLog = [];
      chrome.storage.local.remove(['findings', 'endpoints', 'auditLog']);
      sendResponse({ ok: true });
      break;

    default:
      sendResponse({ error: 'Unknown message type' });
  }
  return true;
});

// ============================================================
// REQUEST REPLAY
// ============================================================

// Handle replay request from CLI
async function handleReplayRequest(msg) {
  const { id, url, method, headers, body } = msg;
  try {
    const fetchOpts = {
      method: method || 'GET',
      headers: headers || {},
      credentials: 'include',
    };
    // Only add body for methods that support it
    if (body && !['GET', 'HEAD'].includes((method || 'GET').toUpperCase())) {
      fetchOpts.body = body;
    }
    const response = await fetch(url, fetchOpts);

    const responseBody = await response.text();
    const responseHeaders = {};
    response.headers.forEach((v, k) => responseHeaders[k.toLowerCase()] = v);

    ws.send(JSON.stringify({
      type: 'replayResponse',
      id,
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
    }));
  } catch (e) {
    ws.send(JSON.stringify({
      type: 'error',
      id,
      error: e.name,
      message: e.message,
    }));
  }
}

// Handle replay request from popup
async function handleReplayFromPopup(request) {
  try {
    const fetchOpts = {
      method: request.method || 'GET',
      headers: request.headers || {},
      credentials: 'include',
    };
    // Only add body for methods that support it
    if (request.body && !['GET', 'HEAD'].includes((request.method || 'GET').toUpperCase())) {
      fetchOpts.body = request.body;
    }
    const response = await fetch(request.url, fetchOpts);

    const body = await response.text();
    const headers = {};
    response.headers.forEach((v, k) => headers[k] = v);

    return {
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ============================================================
// DEEP SCAN TRIGGER (Send to Lonkero CLI)
// ============================================================

async function triggerDeepScan() {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return { error: 'Not connected to Lonkero CLI' };
  }

  // Send discovered data to CLI for deep scanning
  ws.send(JSON.stringify({
    type: 'deepScanRequest',
    data: {
      endpoints: state.endpoints,
      findings: state.findings,
      sessions: Object.fromEntries(state.sessions),
    },
  }));

  return { ok: true, message: 'Deep scan triggered' };
}

// ============================================================
// LOCAL INTRUDER ATTACK (when CLI not connected)
// ============================================================

async function runLocalIntruderAttack(template, payloads) {
  const results = [];
  const baselineLength = null;

  for (let i = 0; i < payloads.length; i++) {
    const payload = payloads[i];
    const request = parseTemplateRequest(template, payload);

    try {
      const startTime = performance.now();
      const response = await fetch(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        credentials: 'include',
      });

      const body = await response.text();
      const duration = Math.round(performance.now() - startTime);

      results.push({
        index: i + 1,
        payload: payload,
        status: response.status,
        length: body.length,
        time: duration,
        interesting: baselineLength && Math.abs(body.length - baselineLength) > 50,
      });

      // Set baseline from first request
      if (i === 0) {
        results[0].baselineLength = body.length;
      }
    } catch (e) {
      results.push({
        index: i + 1,
        payload: payload,
        status: 0,
        length: 0,
        time: 0,
        error: e.message,
      });
    }

    // Rate limiting
    await new Promise(r => setTimeout(r, 100));
  }

  return results;
}

function parseTemplateRequest(template, payload) {
  // Replace markers with payload
  const filled = template.replace(/§[^§]*§/g, payload);

  const lines = filled.split('\n');
  const [method, path] = (lines[0] || 'GET /').split(' ');
  const headers = {};
  let bodyStart = -1;

  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '') {
      bodyStart = i + 1;
      break;
    }
    const colonIndex = lines[i].indexOf(':');
    if (colonIndex > 0) {
      headers[lines[i].substring(0, colonIndex).trim()] = lines[i].substring(colonIndex + 1).trim();
    }
  }

  const body = bodyStart > 0 ? lines.slice(bodyStart).join('\n') : undefined;
  const host = headers['Host'] || headers['host'] || 'localhost';
  const url = path.startsWith('http') ? path : `https://${host}${path}`;

  return { method: method || 'GET', url, headers, body };
}

// ============================================================
// INITIALIZATION
// ============================================================

// Storage version - increment to clear old findings when patterns change
const STORAGE_VERSION = 5;

// Load persisted state (with version check to clear old data)
chrome.storage.local.get(['auditLog', 'findings', 'endpoints', 'storageVersion'], (result) => {
  // Clear old findings if storage version changed (pattern updates)
  if (result.storageVersion !== STORAGE_VERSION) {
    console.log('[Lonkero] Storage version changed, clearing old findings');
    chrome.storage.local.set({ storageVersion: STORAGE_VERSION, findings: [], endpoints: [] });
    // Don't load old findings
  } else {
    if (result.auditLog) state.auditLog = result.auditLog;
    if (result.findings) state.findings = result.findings;
    if (result.endpoints) state.endpoints = result.endpoints;
  }
});

// Start connection
connect();

// Heartbeat
setInterval(() => {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'heartbeat' }));
  }
}, 25000);

// Persist findings periodically
setInterval(() => {
  chrome.storage.local.set({
    findings: state.findings,
    endpoints: state.endpoints,
  });
}, 30000);

console.log('[Lonkero] Background service worker started');
