// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

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
const LONKERO_LICENSE_API = 'https://lonkero.bountyy.fi/api/v1/validate';
let ws = null;
let reconnectInterval = null;

// ============================================================
// LICENSE MANAGEMENT
// ============================================================

let licenseState = {
  valid: false,
  licenseKey: null,
  licenseType: null,
  licensee: null,
  features: [],
  lastValidated: null,
  // When CLI connects and confirms license, trust that
  cliValidated: false,
};

/**
 * Validate license key against Bountyy license server.
 * Uses the existing /api/v1/validate endpoint (no new APIs).
 */
async function validateLicense(key) {
  if (!key) {
    licenseState.valid = false;
    licenseState.licenseType = null;
    licenseState.licensee = null;
    licenseState.features = [];
    await persistLicenseState();
    return false;
  }

  const _p = key.split('-');
  if (_p.length !== 5 || _p[0].charCodeAt(0) !== 76 || _p[0].length !== 7) {
    licenseState.valid = false;
    await persistLicenseState();
    return false;
  }
  for (let i = 1; i < 5; i++) {
    if (_p[i].length !== 4 || !/^[A-Z0-9]+$/.test(_p[i])) {
      licenseState.valid = false;
      await persistLicenseState();
      return false;
    }
  }

  try {
    const response = await fetch(LONKERO_LICENSE_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Product': 'lonkero-extension',
        'X-Version': chrome.runtime.getManifest().version,
      },
      body: JSON.stringify({
        license_key: key,
        product: 'lonkero',
        version: chrome.runtime.getManifest().version,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      const _vt = ['Personal','Professional','Team','Enterprise'];
      if (data.valid === true && !data.killswitch_active && _vt.includes(data.license_type)) {
        licenseState.valid = true;
        licenseState.licenseKey = key;
        licenseState.licenseType = data.license_type || null;
        licenseState.licensee = data.licensee || null;
        licenseState.features = data.features || [];
        licenseState.lastValidated = Date.now();
        console.log('[Lonkero] License validated:', data.license_type, data.licensee);
        await persistLicenseState();
        if (self.lonkeroTracker) self.lonkeroTracker.track('license_validated', { type: data.license_type });
        return true;
      }
    }
  } catch (e) {
    console.warn('[Lonkero] License validation failed:', e.message);
    // Offline grace: only if re-validating the SAME key that was previously valid
    // A new/different key must always be server-validated
    if (licenseState.valid && licenseState.lastValidated && licenseState.licenseKey === key) {
      const hoursSinceValidation = (Date.now() - licenseState.lastValidated) / (1000 * 60 * 60);
      if (hoursSinceValidation < 24) {
        console.log('[Lonkero] Using cached license (validated', Math.round(hoursSinceValidation), 'hours ago)');
        return true;
      }
    }
  }

  licenseState.valid = false;
  await persistLicenseState();
  if (self.lonkeroTracker) self.lonkeroTracker.track('license_invalid');
  return false;
}

/**
 * Check if the extension is licensed (any paid tier).
 */
function isLicensed() {
  return licenseState.valid || licenseState.cliValidated;
}

/**
 * Get the license key for scanner file verification.
 * Scanner files independently validate against the Bountyy license server.
 * This returns the actual key so scanners can do their own server check.
 */
function getLicenseKeyForScanners() {
  if (!isLicensed() || !licenseState.licenseKey) return null;
  return licenseState.licenseKey;
}

/**
 * Persist license state to chrome.storage.
 */
async function persistLicenseState() {
  await chrome.storage.local.set({
    licenseKey: licenseState.licenseKey,
    licenseValid: licenseState.valid,
    licenseType: licenseState.licenseType,
    licensee: licenseState.licensee,
    licenseFeatures: licenseState.features,
    licenseLastValidated: licenseState.lastValidated,
  });
}

/**
 * Load license state from chrome.storage and re-validate.
 */
async function loadAndValidateLicense() {
  const stored = await chrome.storage.local.get([
    'licenseKey', 'licenseValid', 'licenseType', 'licensee',
    'licenseFeatures', 'licenseLastValidated',
  ]);

  if (stored.licenseKey && typeof stored.licenseKey === 'string') {
    const sp = stored.licenseKey.split('-');
    if (sp.length !== 5 || sp[0].charCodeAt(0) !== 76 || sp[0].length !== 7 || !sp.slice(1).every(s => s.length === 4 && /^[A-Z0-9]+$/.test(s))) {
      licenseState.valid = false;
      await persistLicenseState();
      return;
    }
    licenseState.licenseKey = stored.licenseKey;
    licenseState.valid = stored.licenseValid || false;
    licenseState.licenseType = stored.licenseType || null;
    licenseState.licensee = stored.licensee || null;
    licenseState.features = stored.licenseFeatures || [];
    licenseState.lastValidated = stored.licenseLastValidated || null;

    // Re-validate with server
    await validateLicense(stored.licenseKey);
  }
}

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
      if (self.lonkeroTracker) self.lonkeroTracker.track('cli_connected');
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
      const wasConnected = state.connected;
      console.log('[Lonkero] Disconnected');
      state.connected = false;
      ws = null;
      if (wasConnected) {
        audit('DISCONNECTED', '', '', 'Session ended');
        if (self.lonkeroTracker) self.lonkeroTracker.track('cli_disconnected');
      }

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
      if (self.lonkeroTracker) self.lonkeroTracker.track('scope_set', { count: state.scope.length });
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

    case 'licenseValidated':
      // CLI has validated the license server-side; trust this connection
      licenseState.cliValidated = true;
      licenseState.valid = true;
      if (msg.licenseType) licenseState.licenseType = msg.licenseType;
      if (msg.licensee) licenseState.licensee = msg.licensee;
      console.log('[Lonkero] License validated via CLI:', msg.licenseType);
      if (self.lonkeroTracker) self.lonkeroTracker.track('license_cli_validated', { type: msg.licenseType });
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
        // License info
        licensed: isLicensed(),
        licenseType: licenseState.licenseType,
        licensee: licenseState.licensee,
      });
      break;

    // License management
    case 'getLicenseState':
      sendResponse({
        valid: isLicensed(),
        licenseType: licenseState.licenseType,
        licensee: licenseState.licensee,
        licenseKey: licenseState.licenseKey ? '****' + licenseState.licenseKey.slice(-4) : null,
        lastValidated: licenseState.lastValidated,
      });
      break;

    case 'setLicenseKey':
      validateLicense(message.key).then((valid) => {
        if (self.lonkeroTracker) self.lonkeroTracker.track('license_activate', { success: valid, type: licenseState.licenseType });
        sendResponse({ valid, licenseType: licenseState.licenseType, licensee: licenseState.licensee });
      });
      return true; // Async response

    case 'removeLicenseKey':
      licenseState.valid = false;
      licenseState.licenseKey = null;
      licenseState.licenseType = null;
      licenseState.licensee = null;
      licenseState.features = [];
      licenseState.lastValidated = null;
      licenseState.cliValidated = false;
      persistLicenseState();
      if (self.lonkeroTracker) self.lonkeroTracker.track('license_removed');
      sendResponse({ ok: true });
      break;

    case 'checkLicense':
      // Content scripts can check if licensed
      // Includes the license key so scanner files can independently validate
      // against the Bountyy server (defense-in-depth)
      sendResponse({
        licensed: isLicensed(),
        key: isLicensed() ? getLicenseKeyForScanners() : null,
      });
      break;

    // Control commands
    case 'startMonitoring':
      if (!isLicensed()) {
        sendResponse({ ok: false, error: 'license_required' });
        break;
      }
      state.monitoring = true;
      if (self.lonkeroTracker) self.lonkeroTracker.track('monitoring_start');
      sendResponse({ ok: true });
      break;

    case 'stopMonitoring':
      state.monitoring = false;
      if (self.lonkeroTracker) self.lonkeroTracker.track('monitoring_stop');
      sendResponse({ ok: true });
      break;

    case 'pause':
      state.paused = true;
      audit('PAUSED', '', '', 'By user');
      if (self.lonkeroTracker) self.lonkeroTracker.track('scan_pause');
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'userPaused' }));
      }
      sendResponse({ ok: true });
      break;

    case 'resume':
      state.paused = false;
      audit('RESUMED', '', '', 'By user');
      if (self.lonkeroTracker) self.lonkeroTracker.track('scan_resume');
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
      // License gate: silently drop findings from unlicensed sessions.
      // This is the strongest defense layer - background.js cannot be modified
      // from page context, so even fully stripped scanner files can't bypass this.
      if (!isLicensed()) {
        console.debug('[Background] Finding dropped: no valid license');
        sendResponse({ ok: false, error: 'license_required' });
        break;
      }
      console.log('[Background] Received finding:', message.finding?.type, message.finding);
      const finding = {
        ...message.finding,
        id: state.findings.length + 1,
        tabId: sender.tab?.id,
        tabUrl: sender.tab?.url,
      };

      // Types that should dedupe by type+url only (not by value)
      const dedupeByTypeAndUrlOnly = [
        'Finnish Y-tunnus', 'Finnish HETU', 'IBAN', 'Credit Card',
        'Mapbox Public Token', 'KEY_DETECTED', 'AUTH_COOKIE', 'AUTH_LOCALSTORAGE',
        'CLOUD_STORAGE', 'DOM_XSS_SOURCE', 'DOM_XSS_POTENTIAL',
        // Security headers (one per type per URL)
        'MISSING_SECURITY_HEADER', 'WEAK_CSP', 'PERMISSIVE_CORS', 'SERVER_DISCLOSURE',
        // Cookies & JWT
        'INSECURE_COOKIE', 'JWT_INFO', 'JWT_EXPIRED', 'JWT_NO_EXPIRY',
        // Other security checks
        'SOURCE_MAP_EXPOSED', 'MIXED_CONTENT', 'OPEN_REDIRECT_PARAM',
        // GraphQL findings (one per type per endpoint)
        'GRAPHQL_INTROSPECTION_ENABLED', 'GRAPHQL_NO_DEPTH_LIMIT', 'GRAPHQL_BATCHING_ENABLED',
        'GRAPHQL_NO_ALIAS_LIMIT', 'GRAPHQL_DEBUG_MODE', 'GRAPHQL_FIELD_SUGGESTIONS',
        'GRAPHQL_APQ_ENABLED', 'GRAPHQL_SERVER_FINGERPRINT', 'GRAPHQL_ENDPOINT_405',
        'GRAPHQL_AUTH_REQUIRED', 'GRAPHQL_WEBSOCKET_ENDPOINT',
        // WordPress CMS findings (one per type per site)
        'WP_VERSION_DISCLOSURE', 'WP_USER_ENUMERATION', 'WP_REST_API_USER_ENUM',
        'WP_XMLRPC_ENABLED', 'WP_DEBUG_LOG_EXPOSED', 'WP_CONFIG_EXPOSED',
        'WP_INSTALL_SCRIPT_ACCESSIBLE', 'WP_DIRECTORY_LISTING', 'WP_CRON_EXPOSED',
        'WP_VULNERABLE_PLUGIN', 'WP_SQL_DUMP_EXPOSED', 'WP_PHPMYADMIN_EXPOSED',
        'WP_SETUP_CONFIG_ACCESSIBLE', 'WP_REST_API_INDEX', 'WP_UPGRADE_SCRIPT',
        'WP_BACKUP_DIR_EXPOSED', 'WP_THEME_EDITOR_ACCESSIBLE',
        // Drupal CMS findings
        'DRUPAL_VERSION_DISCLOSURE', 'DRUPAL_DRUPALGEDDON', 'DRUPAL_DRUPALGEDDON2',
        'DRUPAL_DRUPALGEDDON3', 'DRUPAL_USER_ENUMERATION', 'DRUPAL_JSONAPI_USER_ENUM',
        'DRUPAL_API_EXPOSED', 'DRUPAL_ADMIN_ACCESSIBLE', 'DRUPAL_INSTALL_SCRIPT',
        'DRUPAL_CONFIG_EXPOSED', 'DRUPAL_CRON_EXPOSED', 'DRUPAL_PRIVATE_FILES_EXPOSED',
        'DRUPAL_VIEWS_ENDPOINT', 'DRUPAL_BACKUP_EXPOSED', 'DRUPAL_MODULE_INFO_EXPOSED',
        // Joomla CMS findings
        'JOOMLA_VERSION_DISCLOSURE', 'JOOMLA_CVE_2023_23752', 'JOOMLA_CVE_2017_8917',
        'JOOMLA_ADMIN_ACCESSIBLE', 'JOOMLA_API_EXPOSED', 'JOOMLA_CONFIG_EXPOSED',
        'JOOMLA_INSTALL_DIR',
        // Laravel findings
        'LARAVEL_ENV_EXPOSED', 'LARAVEL_IGNITION_EXPOSED', 'LARAVEL_TELESCOPE_EXPOSED',
        'LARAVEL_HORIZON_EXPOSED', 'LARAVEL_LOG_EXPOSED', 'LARAVEL_DEBUG_MODE',
        'LARAVEL_STORAGE_LISTING', 'LARAVEL_BACKUP_EXPOSED', 'LARAVEL_NOVA_EXPOSED',
        'LARAVEL_ARTISAN_EXPOSED',
        // Liferay findings
        'LIFERAY_JSONWS_EXPOSED', 'LIFERAY_WEBDAV_EXPOSED', 'LIFERAY_AXIS_EXPOSED',
        'LIFERAY_VERSION_DISCLOSURE',
        // Next.js findings
        'NEXTJS_SENSITIVE_DATA', 'NEXTJS_DEBUG_MODE', 'NEXTJS_API_EXPOSED',
        'NEXTJS_IMAGE_SSRF', 'NEXTJS_MIDDLEWARE_BYPASS', 'NEXTJS_SOURCE_MAPS',
        'NEXTJS_DATA_EXPOSURE',
        // Other framework findings
        'REACT_DEVTOOLS_PRODUCTION', 'REACT_DANGEROUS_INNERHTML',
        'VUE_DEVTOOLS_PRODUCTION', 'VUE_V_HTML_USAGE',
        'ANGULAR_BYPASS_SECURITY',
        'DJANGO_DEBUG_MODE', 'DJANGO_ADMIN_EXPOSED',
        // Framework scanner findings
        'FRAMEWORK_DETECTED', 'ASPNET_YSOD', 'ASPNET_BLAZOR_DEBUG', 'ASPNET_SIGNALR',
        'ASPNET_CONFIG_EXPOSED', 'ASPNET_SWAGGER',
        'SPRING_ACTUATOR', 'SPRING_H2_CONSOLE', 'SPRING_JOLOKIA', 'SPRING_SWAGGER',
        'NEXTJS_SOURCEMAPS', 'NEXTJS_CONFIG_EXPOSED', 'NEXTJS_CVE',
        // General disclosure findings
        'GIT_EXPOSED', 'SVN_EXPOSED', 'ENV_FILE_EXPOSED', 'PHPINFO_EXPOSED',
        'SERVER_STATUS_EXPOSED', 'BACKUP_FILE_EXPOSED', 'ADMIN_PANEL_FOUND',
        'CLOUD_CREDENTIALS_EXPOSED', 'IDE_FILES_EXPOSED', 'PACKAGE_FILE_EXPOSED',
        'SENSITIVE_DIR_LISTING', 'ERROR_PAGE_DISCLOSURE', 'ROBOTS_INTERESTING_PATHS',
      ];

      let findingKey;
      if (dedupeByTypeAndUrlOnly.includes(finding.type)) {
        // For common findings, dedupe by type + URL only (ignore individual values)
        findingKey = `${finding.type}:${finding.url || finding.tabUrl}`;
      } else {
        // For other findings, include evidence in the key
        findingKey = `${finding.type}:${finding.url || finding.tabUrl}:${finding.evidence || finding.value || ''}`;
      }

      const isDuplicate = state.findings.some(f => {
        let existingKey;
        if (dedupeByTypeAndUrlOnly.includes(f.type)) {
          existingKey = `${f.type}:${f.url || f.tabUrl}`;
        } else {
          existingKey = `${f.type}:${f.url || f.tabUrl}:${f.evidence || f.value || ''}`;
        }
        return existingKey === findingKey;
      });

      if (!isDuplicate) {
        state.findings.push(finding);
        console.log('[Background] Finding stored:', finding.type, '| Total findings:', state.findings.length);
        if (self.lonkeroTracker) self.lonkeroTracker.track('finding', { type: finding.type, total: state.findings.length });

        // Forward to CLI if connected
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'finding', finding }));
        }
      } else {
        console.log('[Background] Duplicate finding ignored:', finding.type);
      }
      sendResponse({ ok: true });
      break;

    // Endpoint discovery
    case 'endpointDiscovered':
      if (!isLicensed()) { sendResponse({ ok: false }); break; }
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

    // Request captured from content script - license required
    case 'requestCaptured':
      if (!isLicensed()) { sendResponse({ ok: false }); break; }
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

    case 'getTechnologies':
      // Get technologies from the most recent page analysis
      const techList = [];
      for (const [url, analysis] of state.pageAnalysis) {
        if (analysis.technologies && analysis.technologies.length > 0) {
          techList.push({
            url: url,
            technologies: analysis.technologies,
            frameworks: analysis.frameworks || [],
          });
        }
      }
      sendResponse(techList);
      break;

    // Request replay
    case 'replayRequest':
      if (self.lonkeroTracker) self.lonkeroTracker.track('request_replay', { method: message.request?.method });
      handleReplayFromPopup(message.request).then(sendResponse);
      return true; // Async response

    // Export
    case 'exportAuditLog':
      if (self.lonkeroTracker) self.lonkeroTracker.track('export', { type: 'audit_log', count: state.auditLog.length });
      sendResponse({ log: JSON.stringify(state.auditLog, null, 2) });
      break;

    case 'exportFindings':
      if (self.lonkeroTracker) self.lonkeroTracker.track('export', { type: 'findings', count: state.findings.length });
      sendResponse({
        findings: state.findings,
        endpoints: state.endpoints,
        secrets: state.secrets,
      });
      break;

    // Deep scan trigger
    case 'triggerDeepScan':
      if (!isLicensed()) {
        sendResponse({ error: 'License required. Enter your license key in the extension popup.' });
        return false;
      }
      if (self.lonkeroTracker) self.lonkeroTracker.track('deep_scan', { endpoints: state.endpoints.length, findings: state.findings.length });
      triggerDeepScan().then(sendResponse);
      return true;

    // Clear data
    case 'clearData':
      if (self.lonkeroTracker) self.lonkeroTracker.track('clear_data', { findings: state.findings.length, endpoints: state.endpoints.length });
      state.findings = [];
      state.endpoints = [];
      state.secrets = [];
      state.capturedRequests = [];
      state.auditLog = [];
      chrome.storage.local.remove(['findings', 'endpoints', 'auditLog']);
      sendResponse({ ok: true });
      break;

    // Tracking relay: popup and content scripts send events here
    case 'trackEvent':
      if (self.lonkeroTracker) {
        self.lonkeroTracker.track(message.event, message.props || {});
      }
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
// INITIALIZATION
// ============================================================

// Storage version - increment to clear old findings when patterns change
const STORAGE_VERSION = 4;

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

// Load and validate license before starting
loadAndValidateLicense().then(() => {
  if (isLicensed()) {
    console.log('[Lonkero] License valid:', licenseState.licenseType);
  } else {
    console.log('[Lonkero] No valid license. Extension features are locked.');
    console.log('[Lonkero] Enter your license key in the extension popup to activate.');
  }

  // Start WebSocket connection (always connect - CLI validates its own license)
  connect();
});

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

// Re-validate license periodically (every 6 hours)
setInterval(() => {
  if (licenseState.licenseKey) {
    validateLicense(licenseState.licenseKey);
  }
}, 6 * 60 * 60 * 1000);

console.log('[Lonkero] Background service worker started');

// ============================================================
// Lonkero Extension Analytics - v1
// ============================================================
(function() {
  'use strict';

  const COLLECT_URL = 'https://lonkero.bountyy.fi/e';
  const FLUSH_INTERVAL = 30000;  // Batch send every 30s
  const MAX_QUEUE = 50;          // Max events before forced flush
  const MAX_RETRIES = 2;

  let queue = [];
  let instanceId = null;
  let sessionId = null;
  let sessionStart = null;

  function hex(n) {
    const arr = new Uint8Array(n);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function init() {
    try {
      const stored = await chrome.storage.local.get(['lnk_iid']);
      if (stored.lnk_iid) {
        instanceId = stored.lnk_iid;
      } else {
        instanceId = 'ext_' + hex(12);
        await chrome.storage.local.set({ lnk_iid: instanceId });
      }
    } catch {
      instanceId = 'ext_' + hex(12);
    }
    sessionId = 'ses_' + hex(8);
    sessionStart = Date.now();
  }

  function track(event, props) {
    if (!instanceId) return;
    queue.push({
      e: event,
      p: props || {},
      t: Date.now(),
      s: sessionId,
    });
    if (queue.length >= MAX_QUEUE) flush();
  }

  async function flush() {
    if (queue.length === 0 || !instanceId) return;
    const batch = queue.splice(0, MAX_QUEUE);
    const ts = Date.now();
    const nonce = hex(8);

    const payload = {
      iid: instanceId,
      ts: ts,
      n: nonce,
      v: chrome.runtime.getManifest().version || '0.0.0',
      events: batch,
    };

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const res = await fetch(COLLECT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok || res.status === 204) return;
        if (res.status === 429 || res.status >= 500) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        return;
      } catch {
        if (attempt < MAX_RETRIES) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        }
      }
    }
  }

  setInterval(flush, FLUSH_INTERVAL);

  if (typeof self !== 'undefined' && self.addEventListener) {
    self.addEventListener('beforeunload', flush);
  }

  self.lonkeroTracker = { track, flush, init };

  init().then(() => {
    track('ext_loaded', {
      browser: navigator.userAgent.includes('Vivaldi') ? 'vivaldi'
        : navigator.userAgent.includes('OPR') ? 'opera'
        : navigator.userAgent.includes('Brave') ? 'brave'
        : navigator.userAgent.includes('Edg') ? 'edge' : 'chrome',
    });
  });
})();
