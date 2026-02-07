// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Browser-Assist Popup UI
 * Full security testing dashboard with request editor/replayer
 */

let currentState = null;
let capturedRequests = [];
let isExtensionLicensed = false;

function _t(event, props) {
  try { chrome.runtime.sendMessage({ type: 'trackEvent', event, props }); } catch {}
}

// ============================================================
// LICENSE GATE
// ============================================================

function showLicenseGate() {
  const gate = document.getElementById('licenseGate');
  if (gate) {
    gate.style.display = 'block';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}

function hideLicenseGate() {
  const gate = document.getElementById('licenseGate');
  if (gate) gate.style.display = 'none';
}

function updateLicenseIndicator(licenseType, licensee) {
  const indicator = document.getElementById('licenseIndicator');
  const text = document.getElementById('licenseIndicatorText');
  if (indicator && text && licenseType) {
    text.textContent = licenseType + (licensee ? ' - ' + licensee : '');
    indicator.style.display = 'block';
  }
}

function checkLicenseState() {
  chrome.runtime.sendMessage({ type: 'getLicenseState' }, (response) => {
    if (response && response.valid) {
      isExtensionLicensed = true;
      hideLicenseGate();
      updateLicenseIndicator(response.licenseType, response.licensee);
    } else {
      isExtensionLicensed = false;
      showLicenseGate();
    }
  });
}

// Activate license button handler
document.getElementById('activateLicenseBtn')?.addEventListener('click', () => {
  const input = document.getElementById('licenseKeyInput');
  const errorEl = document.getElementById('licenseError');
  const successEl = document.getElementById('licenseSuccess');
  const key = input?.value?.trim();

  errorEl.style.display = 'none';
  successEl.style.display = 'none';

  if (!key) {
    errorEl.textContent = 'Please enter a license key.';
    errorEl.style.display = 'block';
    return;
  }

  const _kp = key.split('-');
  if (_kp.length !== 5 || _kp[0].charCodeAt(0) !== 76 || _kp[0].length !== 7 || !_kp.slice(1).every(p => p.length === 4 && /^[A-Z0-9]+$/.test(p))) {
    errorEl.textContent = 'Invalid key.';
    errorEl.style.display = 'block';
    return;
  }

  // Show loading state
  const btn = document.getElementById('activateLicenseBtn');
  btn.disabled = true;
  btn.textContent = 'Validating...';

  chrome.runtime.sendMessage({ type: 'setLicenseKey', key }, (response) => {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="key"></i> Activate License';
    if (typeof lucide !== 'undefined') lucide.createIcons();

    if (response && response.valid) {
      isExtensionLicensed = true;
      successEl.textContent = 'License activated! ' + (response.licenseType || '') + ' - ' + (response.licensee || '');
      successEl.style.display = 'block';
      updateLicenseIndicator(response.licenseType, response.licensee);
      _t('popup_license_ok', { type: response.licenseType });
      // Hide gate after a brief delay
      setTimeout(() => hideLicenseGate(), 800);
    } else {
      errorEl.textContent = 'Invalid license key. Please check and try again.';
      errorEl.style.display = 'block';
      _t('popup_license_fail');
    }
  });
});

// ============================================================
// CONSENT MANAGEMENT
// ============================================================

const CONSENT_KEY = 'lonkero_analytics_consent';

function checkConsentAnswered() {
  const val = localStorage.getItem(CONSENT_KEY);
  return val === 'accepted' || val === 'declined';
}

function checkConsentAccepted() {
  return localStorage.getItem(CONSENT_KEY) === 'accepted';
}

function showConsentModal() {
  const modal = document.getElementById('consentModal');
  if (modal) {
    modal.style.display = 'block';
    // Re-render icons in modal
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }
}

function hideConsentModal() {
  const modal = document.getElementById('consentModal');
  if (modal) {
    modal.style.display = 'none';
  }
}

function acceptConsent() {
  localStorage.setItem(CONSENT_KEY, 'accepted');
  chrome.storage.local.set({ analytics_consent: 'accepted' });
  hideConsentModal();
  _t('consent_accepted');
  trackUsage(); // Track now that consent is given
}

function declineConsent() {
  localStorage.setItem(CONSENT_KEY, 'declined');
  chrome.storage.local.set({ analytics_consent: 'declined' });
  hideConsentModal();
}

// Setup consent button handlers
document.getElementById('acceptConsentBtn')?.addEventListener('click', acceptConsent);
document.getElementById('declineConsentBtn')?.addEventListener('click', declineConsent);

// ============================================================
// TAB NAVIGATION
// ============================================================

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const tabName = tab.dataset.tab;
    _t('tab_switch', { tab: tabName });

    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabName}`).classList.add('active');

    // Load tab data
    if (tabName === 'findings') loadFindings();
    if (tabName === 'secrets') loadSecrets();
    if (tabName === 'endpoints') loadEndpoints();
    if (tabName === 'requests') loadRequests();
  });
});

// ============================================================
// STATE MANAGEMENT
// ============================================================

function updateUI(state) {
  currentState = state;

  // Sync license state from background
  if (state.licensed !== undefined) {
    if (state.licensed && !isExtensionLicensed) {
      isExtensionLicensed = true;
      hideLicenseGate();
      updateLicenseIndicator(state.licenseType, state.licensee);
    }
  }

  const statusBar = document.getElementById('statusBar');
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const scopeDisplay = document.getElementById('scopeDisplay');

  // Update connection status
  if (state.monitoring) {
    if (state.paused) {
      statusBar.className = 'status-bar monitoring';
      statusDot.className = 'dot blue';
      statusText.textContent = state.connected ? 'Paused (CLI Connected)' : 'Paused';
    } else {
      statusBar.className = 'status-bar monitoring';
      statusDot.className = 'dot blue';
      statusText.textContent = state.connected ? 'Monitoring (CLI Connected)' : 'Monitoring';
    }
  } else if (state.connected) {
    statusBar.className = 'status-bar connected';
    statusDot.className = 'dot green';
    statusText.textContent = 'CLI Connected';
  } else {
    statusBar.className = 'status-bar disconnected';
    statusDot.className = 'dot red';
    statusText.textContent = 'Ready (CLI Not Connected)';
  }

  // Update scope display
  if (scopeDisplay) {
    if (state.scope && state.scope.length > 0) {
      scopeDisplay.textContent = state.scope.join(', ');
    } else {
      scopeDisplay.textContent = '';
    }
  }

  // Update stats
  document.getElementById('findingsCount').textContent = state.findingsCount || 0;
  const secretsEl = document.getElementById('secretsCount');
  if (secretsEl) secretsEl.textContent = state.secretsCount || 0;
  document.getElementById('endpointsCount').textContent = state.endpointsCount || 0;
  document.getElementById('requestsCount').textContent = state.requestsProxied || 0;

  // Update findings badge
  const badge = document.getElementById('findingsBadge');
  if (badge) {
    if (state.findingsCount > 0) {
      badge.textContent = state.findingsCount;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
  }

  // Update button states
  const startBtn = document.getElementById('startBtn');
  const pauseBtn = document.getElementById('pauseBtn');
  const deepScanBtn = document.getElementById('deepScanBtn');

  if (state.monitoring) {
    startBtn.innerHTML = '<i data-lucide="square"></i> Stop Monitoring';
    startBtn.className = 'btn btn-danger';
  } else {
    startBtn.innerHTML = '<i data-lucide="play"></i> Start Monitoring';
    startBtn.className = 'btn btn-primary';
  }

  pauseBtn.innerHTML = state.paused ? '<i data-lucide="play"></i> Resume' : '<i data-lucide="pause"></i> Pause';

  // Re-render icons
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }
  deepScanBtn.disabled = !state.connected;
}

function refreshState() {
  chrome.runtime.sendMessage({ type: 'getState' }, (response) => {
    if (response) {
      updateUI(response);
    }
  });
}

// ============================================================
// TECHNOLOGIES DISPLAY
// ============================================================

function loadTechnologies() {
  chrome.runtime.sendMessage({ type: 'getTechnologies' }, (techData) => {
    const container = document.getElementById('technologiesList');
    if (!container) return;

    if (!techData || techData.length === 0) {
      container.innerHTML = '<span style="color: #555; font-size: 10px;">Browse a site to detect...</span>';
      return;
    }

    // Flatten and dedupe technologies
    const seen = new Set();
    const allTechs = [];

    for (const page of techData) {
      for (const tech of (page.technologies || [])) {
        const key = tech.name;
        if (!seen.has(key)) {
          seen.add(key);
          allTechs.push(tech);
        }
      }
      for (const fw of (page.frameworks || [])) {
        const key = fw.name;
        if (!seen.has(key)) {
          seen.add(key);
          allTechs.push({ ...fw, category: 'framework' });
        }
      }
    }

    if (allTechs.length === 0) {
      container.innerHTML = '<span style="color: #555; font-size: 10px;">No technologies detected</span>';
      return;
    }

    container.innerHTML = allTechs.map(t => {
      const category = t.category || 'framework';
      const version = t.version && t.version !== 'unknown' ? ` ${t.version}` : '';
      return `<span class="tech-tag ${category}" title="${t.evidence || ''}">${escapeHtml(t.name)}${version}</span>`;
    }).join('');
  });
}

// ============================================================
// FINDINGS TAB
// ============================================================

let currentFindings = [];

function loadFindings() {
  chrome.runtime.sendMessage({ type: 'getFindings' }, (findings) => {
    const container = document.getElementById('findingsList');
    if (!container) return;

    currentFindings = findings || [];

    if (!findings || findings.length === 0) {
      container.innerHTML = '<div class="empty-state">No findings yet. Browse the target site to detect vulnerabilities.</div>';
      return;
    }

    container.innerHTML = findings.map((f, i) => {
      const severity = getSeverity(f.type);
      const evidence = f.evidence || f.value || f.valuePreview || f.description || '';
      return `
        <div class="item ${severity} finding-item" data-index="${i}">
          <div class="item-header">
            <span class="item-type">${escapeHtml(f.type)}</span>
            <span class="item-badge" style="background: transparent; border: 1px solid ${severity === 'critical' ? '#ff3939' : severity === 'high' ? '#ff6600' : '#ffaa00'}; color: ${severity === 'critical' ? '#ff3939' : severity === 'high' ? '#ff6600' : '#ffaa00'}; font-size: 8px;">${severity.toUpperCase()}</span>
          </div>
          <div class="item-url">${escapeHtml(f.url || f.tabUrl || 'Unknown')}</div>
          ${evidence ? `<div class="item-detail">${escapeHtml(evidence.substring(0, 100))}${evidence.length > 100 ? '...' : ''}</div>` : ''}
        </div>
      `;
    }).join('');

    // Add click handlers
    container.querySelectorAll('.finding-item').forEach(item => {
      item.addEventListener('click', () => {
        const index = parseInt(item.dataset.index, 10);
        showFindingDetail(index);
      });
    });
  });
}

function showFindingDetail(index) {
  const finding = currentFindings[index];
  if (!finding) return;

  const detailView = document.getElementById('findingDetail');
  document.getElementById('findingDetailType').textContent = finding.type;
  document.getElementById('findingDetailUrl').textContent = finding.url || finding.tabUrl || 'Unknown';

  // Build detailed data
  const details = { ...finding };
  delete details.id;
  delete details.tabId;
  document.getElementById('findingDetailData').value = JSON.stringify(details, null, 2);

  detailView.style.display = 'block';
}

// Finding detail buttons
document.getElementById('closeFindingBtn')?.addEventListener('click', () => {
  document.getElementById('findingDetail').style.display = 'none';
});

document.getElementById('copyFindingBtn')?.addEventListener('click', () => {
  const data = document.getElementById('findingDetailData').value;
  navigator.clipboard.writeText(data).then(() => {
    const btn = document.getElementById('copyFindingBtn');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = '📋 Copy', 1500);
  });
});

function getSeverity(type) {
  const severities = {
    // XSS related
    'DOM_XSS_SINK': 'critical',
    'DOM_XSS_SOURCE': 'high',
    'DOM_XSS_POTENTIAL': 'high',
    'DOM_XSS': 'critical',
    'REFLECTED_XSS': 'critical',
    'XSS': 'critical',
    // Framework scanner
    'NEXTJS_MIDDLEWARE_BYPASS': 'critical',
    'NEXTJS_DATA_EXPOSURE': 'high',
    'NEXTJS_IMAGE_SSRF': 'high',
    'SPRING_ACTUATOR_EXPOSED': 'high',
    'SPRING_H2_CONSOLE': 'critical',
    'SPRING_JOLOKIA': 'critical',
    'ASPNET_YSOD': 'medium',
    'ASPNET_BLAZOR_DEBUG': 'medium',
    'ASPNET_CONFIG_EXPOSED': 'high',
    // Injection
    'PROTOTYPE_POLLUTION': 'critical',
    'PROTOTYPE_POLLUTION_ATTEMPT': 'high',
    'SQLi': 'critical',
    // Secrets & Auth
    'SECRET_EXPOSED': 'critical',
    'AUTH_COOKIE': 'high',
    'AUTH_LOCALSTORAGE': 'high',
    'KEY_DETECTED': 'info',
    'INSECURE_COOKIE': 'medium',
    // Libraries
    'VULNERABLE_LIBRARY': 'high',
    // Cloud & Storage
    'CLOUD_STORAGE': 'medium',
    // Security Headers
    'MISSING_SECURITY_HEADER': 'low',
    'WEAK_CSP': 'medium',
    'PERMISSIVE_CORS': 'medium',
    'SERVER_DISCLOSURE': 'info',
    // JWT
    'JWT_VULNERABILITY': 'critical',
    'JWT_INFO': 'info',
    'JWT_EXPIRED': 'low',
    'JWT_NO_EXPIRY': 'medium',
    'JWT_SENSITIVE_DATA': 'high',
    // Source & Paths
    'SOURCE_MAP_EXPOSED': 'low',
    'SENSITIVE_PATH': 'medium',
    'OPEN_REDIRECT_PARAM': 'medium',
    // Mixed Content
    'MIXED_CONTENT': 'medium',
    // Other
    'DANGEROUS_EVAL': 'medium',
    'Finnish Y-tunnus': 'low',
    'Finnish HETU': 'critical',
    'IBAN': 'high',
    'Credit Card': 'critical',
    // Info level
    'Mapbox Public Token': 'info',
    // GraphQL findings
    'GRAPHQL_INTROSPECTION_ENABLED': 'medium',
    'GRAPHQL_SQL_INJECTION': 'critical',
    'GRAPHQL_SQLI_EXTRACTED_QUERY': 'critical',
    'GRAPHQL_NOSQLI_EXTRACTED_QUERY': 'high',
    'GRAPHQL_XSS_REFLECTION': 'high',
    'GRAPHQL_POTENTIAL_IDOR': 'high',
    'GRAPHQL_IDOR_EXTRACTED_QUERY': 'high',
    'GRAPHQL_DANGEROUS_MUTATION': 'info',
    'GRAPHQL_NO_DEPTH_LIMIT': 'medium',
    'GRAPHQL_BATCHING_ENABLED': 'low',
    'GRAPHQL_NO_ALIAS_LIMIT': 'low',
    'GRAPHQL_DEBUG_MODE': 'medium',
    'GRAPHQL_FIELD_SUGGESTIONS': 'low',
    'GRAPHQL_MUTATION_BATCHING': 'medium',
    'GRAPHQL_ALIAS_COALESCING': 'medium',
    'GRAPHQL_LARGE_BATCH_ALLOWED': 'medium',
    'GRAPHQL_DEEP_NESTING_ALLOWED': 'high',
    'GRAPHQL_CIRCULAR_REFERENCE': 'high',
    'GRAPHQL_APQ_ENABLED': 'info',
    'GRAPHQL_APQ_HASH_FOUND': 'medium',
    'GRAPHQL_APQ_REGISTRATION_OPEN': 'high',
    'GRAPHQL_APQ_BYPASS': 'medium',
    'GRAPHQL_SENSITIVE_FIELD_EXPOSED': 'high',
    'GRAPHQL_MUTATION_AUTH_BYPASS': 'critical',
    'GRAPHQL_TIME_BASED_INJECTION': 'critical',
    'GRAPHQL_ACCESSIBLE_QUERY': 'info',
    'GRAPHQL_EXTRACTED_QUERY_WORKS': 'info',
    'GRAPHQL_PERSISTED_QUERY_FOUND': 'medium',
    'GRAPHQL_SERVER_FINGERPRINT': 'info',
    'GRAPHQL_ENDPOINT_405': 'info',
    'GRAPHQL_AUTH_REQUIRED': 'info',
    'GRAPHQL_SUBSCRIPTION_FOUND': 'info',
    'GRAPHQL_SENSITIVE_SUBSCRIPTION': 'medium',
    'GRAPHQL_WEBSOCKET_ENDPOINT': 'info',
    // Form fuzzer findings
    'FORM_VULNERABILITY': 'high',
    'FORM_SQLI': 'critical',
    'FORM_XSS': 'high',
    'FORM_SSTI': 'high',
    'FORM_CMDI': 'critical',
    // WordPress CMS findings
    'WP_VERSION_DISCLOSURE': 'low',
    'WP_USER_ENUMERATION': 'medium',
    'WP_REST_API_USER_ENUM': 'medium',
    'WP_XMLRPC_ENABLED': 'medium',
    'WP_DEBUG_LOG_EXPOSED': 'high',
    'WP_CONFIG_EXPOSED': 'critical',
    'WP_INSTALL_SCRIPT_ACCESSIBLE': 'critical',
    'WP_DIRECTORY_LISTING': 'low',
    'WP_CRON_EXPOSED': 'info',
    'WP_VULNERABLE_PLUGIN': 'high',
    'WP_SQL_DUMP_EXPOSED': 'critical',
    'WP_PHPMYADMIN_EXPOSED': 'high',
    'WP_SETUP_CONFIG_ACCESSIBLE': 'critical',
    'WP_REST_API_INDEX': 'info',
    'WP_UPGRADE_SCRIPT': 'medium',
    'WP_BACKUP_DIR_EXPOSED': 'high',
    'WP_THEME_EDITOR_ACCESSIBLE': 'info',
    // Drupal CMS findings
    'DRUPAL_VERSION_DISCLOSURE': 'low',
    'DRUPAL_DRUPALGEDDON': 'critical',
    'DRUPAL_DRUPALGEDDON2': 'critical',
    'DRUPAL_DRUPALGEDDON3': 'critical',
    'DRUPAL_USER_ENUMERATION': 'medium',
    'DRUPAL_JSONAPI_USER_ENUM': 'medium',
    'DRUPAL_API_EXPOSED': 'medium',
    'DRUPAL_ADMIN_ACCESSIBLE': 'info',
    'DRUPAL_INSTALL_SCRIPT': 'high',
    'DRUPAL_CONFIG_EXPOSED': 'critical',
    'DRUPAL_CRON_EXPOSED': 'medium',
    'DRUPAL_PRIVATE_FILES_EXPOSED': 'high',
    'DRUPAL_VIEWS_ENDPOINT': 'info',
    'DRUPAL_BACKUP_EXPOSED': 'critical',
    'DRUPAL_MODULE_INFO_EXPOSED': 'low',
    // Joomla CMS findings
    'JOOMLA_VERSION_DISCLOSURE': 'low',
    'JOOMLA_CVE_2023_23752': 'critical',
    'JOOMLA_CVE_2017_8917': 'critical',
    'JOOMLA_ADMIN_ACCESSIBLE': 'info',
    'JOOMLA_API_EXPOSED': 'critical',
    'JOOMLA_CONFIG_EXPOSED': 'critical',
    'JOOMLA_INSTALL_DIR': 'high',
    // Laravel findings
    'LARAVEL_ENV_EXPOSED': 'critical',
    'LARAVEL_IGNITION_EXPOSED': 'critical',
    'LARAVEL_TELESCOPE_EXPOSED': 'high',
    'LARAVEL_HORIZON_EXPOSED': 'medium',
    'LARAVEL_LOG_EXPOSED': 'high',
    'LARAVEL_DEBUG_MODE': 'critical',
    'LARAVEL_STORAGE_LISTING': 'medium',
    'LARAVEL_BACKUP_EXPOSED': 'critical',
    'LARAVEL_NOVA_EXPOSED': 'info',
    'LARAVEL_ARTISAN_EXPOSED': 'critical',
    // Liferay findings
    'LIFERAY_JSONWS_EXPOSED': 'critical',
    'LIFERAY_WEBDAV_EXPOSED': 'high',
    'LIFERAY_AXIS_EXPOSED': 'high',
    'LIFERAY_VERSION_DISCLOSURE': 'low',
    // Next.js findings
    'NEXTJS_SENSITIVE_DATA': 'high',
    'NEXTJS_DEBUG_MODE': 'medium',
    'NEXTJS_API_EXPOSED': 'medium',
    'NEXTJS_IMAGE_SSRF': 'critical',
    'NEXTJS_MIDDLEWARE_BYPASS': 'critical',
    'NEXTJS_SOURCE_MAPS': 'medium',
    'NEXTJS_DATA_EXPOSURE': 'high',
    'NEXTJS_SOURCEMAPS': 'medium',
    'NEXTJS_CONFIG_EXPOSED': 'high',
    'NEXTJS_CVE': 'high',
    // Other framework findings
    'REACT_DEVTOOLS_PRODUCTION': 'low',
    'REACT_DANGEROUS_INNERHTML': 'medium',
    'VUE_DEVTOOLS_PRODUCTION': 'low',
    'VUE_V_HTML_USAGE': 'medium',
    'ANGULAR_BYPASS_SECURITY': 'high',
    'DJANGO_DEBUG_MODE': 'critical',
    'DJANGO_ADMIN_EXPOSED': 'info',
    // Framework scanner findings
    'FRAMEWORK_DETECTED': 'info',
    'ASPNET_YSOD': 'high',
    'ASPNET_BLAZOR_DEBUG': 'medium',
    'ASPNET_SIGNALR': 'low',
    'ASPNET_CONFIG_EXPOSED': 'critical',
    'ASPNET_SWAGGER': 'medium',
    'SPRING_ACTUATOR': 'high',
    'SPRING_H2_CONSOLE': 'critical',
    'SPRING_JOLOKIA': 'critical',
    'SPRING_SWAGGER': 'medium',
    // General disclosure findings
    'GIT_EXPOSED': 'critical',
    'SVN_EXPOSED': 'critical',
    'ENV_FILE_EXPOSED': 'critical',
    'PHPINFO_EXPOSED': 'medium',
    'SERVER_STATUS_EXPOSED': 'medium',
    'BACKUP_FILE_EXPOSED': 'high',
    'ADMIN_PANEL_FOUND': 'info',
    'CLOUD_CREDENTIALS_EXPOSED': 'critical',
    'IDE_FILES_EXPOSED': 'low',
    'PACKAGE_FILE_EXPOSED': 'low',
    'SENSITIVE_DIR_LISTING': 'medium',
    'ERROR_PAGE_DISCLOSURE': 'medium',
    'ROBOTS_INTERESTING_PATHS': 'info',
  };
  return severities[type] || 'medium';
}

// ============================================================
// SECRETS TAB
// ============================================================

function loadSecrets() {
  chrome.runtime.sendMessage({ type: 'getSecrets' }, (secrets) => {
    const container = document.getElementById('secretsList');
    if (!container) return;

    if (!secrets || secrets.length === 0) {
      container.innerHTML = '<div class="empty-state">No secrets found. Browse the site to scan JavaScript for credentials.</div>';
      return;
    }

    container.innerHTML = secrets.map(s => `
      <div class="item critical">
        <div class="item-header">
          <span class="item-type">${escapeHtml(s.type || 'Secret')}</span>
        </div>
        <div class="item-url">${escapeHtml(s.value ? s.value.substring(0, 50) + '...' : 'Hidden')}</div>
        <div class="item-detail">Source: ${escapeHtml(s.source || 'Unknown')}</div>
      </div>
    `).join('');
  });
}

// ============================================================
// ENDPOINTS TAB
// ============================================================

function loadEndpoints() {
  chrome.runtime.sendMessage({ type: 'getEndpoints' }, (endpoints) => {
    const container = document.getElementById('endpointsList');
    if (!container) return;

    if (!endpoints || endpoints.length === 0) {
      container.innerHTML = '<div class="empty-state">No endpoints discovered. Browse the site to discover APIs.</div>';
      return;
    }

    container.innerHTML = endpoints.map((e, i) => `
      <div class="item endpoint-item" data-index="${i}">
        <div class="item-header">
          <span class="endpoint-method">${escapeHtml(e.method)}</span>
          <span class="endpoint-path">${escapeHtml(e.path)}</span>
          ${e.isApi ? '<span class="endpoint-api">API</span>' : ''}
        </div>
      </div>
    `).join('');

    // Store endpoints for click handler
    container.querySelectorAll('.endpoint-item').forEach((item, i) => {
      item.addEventListener('click', () => {
        const ep = endpoints[parseInt(item.dataset.index, 10)];
        if (ep) loadEndpointToEditor(ep.method, ep.url || ep.path);
      });
    });
  });
}

// ============================================================
// REQUESTS TAB
// ============================================================

function loadRequests() {
  chrome.runtime.sendMessage({ type: 'getCapturedRequests' }, (requests) => {
    capturedRequests = requests || [];
    const container = document.getElementById('requestsList');
    if (!container) return;

    if (capturedRequests.length === 0) {
      container.innerHTML = '<div class="empty-state">No requests captured yet. Browse the site to capture traffic.</div>';
      return;
    }

    container.innerHTML = capturedRequests.slice(-50).reverse().map((r, i) => `
      <div class="item request-item" data-index="${capturedRequests.length - 1 - i}">
        <div class="item-header">
          <span class="item-badge ${r.method?.toLowerCase()}">${r.method || 'GET'}</span>
          <span class="item-type">${r.status || 'Pending'}</span>
        </div>
        <div class="item-url">${escapeHtml(r.url)}</div>
        <div class="item-detail">${r.duration ? r.duration + 'ms' : ''}</div>
      </div>
    `).join('');

    // Add click handlers via event delegation
    container.querySelectorAll('.request-item').forEach(item => {
      item.addEventListener('click', () => {
        const index = parseInt(item.dataset.index, 10);
        loadRequestToEditor(index);
      });
    });
  });
}

// Load endpoint into editor
window.loadEndpointToEditor = function(method, url) {
  const editor = document.getElementById('requestEditor');
  if (!editor) return;

  document.getElementById('editorMethod').value = method;
  document.getElementById('editorUrl').value = url;
  document.getElementById('editorHeaders').value = '{}';
  document.getElementById('editorBody').value = '';
  editor.classList.add('active');

  // Switch to requests tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector('[data-tab="requests"]').classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-requests').classList.add('active');
};

// Load captured request into editor
function loadRequestToEditor(index) {
  const req = capturedRequests[index];
  if (!req) {
    console.error('[Lonkero] Request not found at index:', index, 'Total:', capturedRequests.length);
    return;
  }

  const editor = document.getElementById('requestEditor');
  if (!editor) return;

  document.getElementById('editorMethod').value = req.method || 'GET';
  document.getElementById('editorUrl').value = req.url || '';
  document.getElementById('editorHeaders').value = JSON.stringify(req.headers || {}, null, 2);
  document.getElementById('editorBody').value = req.body || '';

  // Show captured response if available
  const responseViewer = document.getElementById('responseViewer');
  const responseStatus = document.getElementById('responseStatus');
  const responseHeadersView = document.getElementById('responseHeadersView');
  const responseBody = document.getElementById('responseBody');

  if (req.responseBody || req.responseHeaders) {
    responseViewer.style.display = 'block';

    // Show status with color coding
    const statusColor = req.status < 300 ? '#39ff14' : req.status < 400 ? '#00aaff' : req.status < 500 ? '#ffaa00' : '#ff3939';
    responseStatus.textContent = `${req.status} ${req.statusText || ''}`;
    responseStatus.style.color = statusColor;

    // Show response headers
    const headerLines = Object.entries(req.responseHeaders || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    responseHeadersView.textContent = headerLines;

    // Show response body (try to pretty-print JSON)
    let bodyText = req.responseBody || '';
    try {
      const parsed = JSON.parse(bodyText);
      bodyText = JSON.stringify(parsed, null, 2);
    } catch (e) {
      // Not JSON, show as-is
    }
    responseBody.value = bodyText;
  } else {
    responseViewer.style.display = 'none';
  }

  editor.classList.add('active');
  console.log('[Lonkero] Loaded request:', req);
}
window.loadRequestToEditor = loadRequestToEditor;

// ============================================================
// BUTTON HANDLERS
// ============================================================

/**
 * Guard function - checks license before allowing scan actions.
 * Returns true if licensed, false if not (and shows gate).
 */
function requireLicense() {
  if (isExtensionLicensed) return true;
  showLicenseGate();
  return false;
}

// Start/Stop Monitoring
document.getElementById('startBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  if (currentState?.monitoring) {
    _t('btn_stop_monitoring');
    chrome.runtime.sendMessage({ type: 'stopMonitoring' }, () => setTimeout(refreshState, 100));
  } else {
    _t('btn_start_monitoring');
    chrome.runtime.sendMessage({ type: 'startMonitoring' }, () => setTimeout(refreshState, 100));
  }
});

// Deep Scan
document.getElementById('deepScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_deep_scan');
  chrome.runtime.sendMessage({ type: 'triggerDeepScan' }, (response) => {
    if (response?.error) {
      alert('Error: ' + response.error);
    } else {
      alert('Deep scan triggered! Check Lonkero CLI for results.');
    }
  });
});

// Fuzz Forms
document.getElementById('fuzzFormsBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_fuzz_forms');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    // First, try to inject formfuzzer.js if not already loaded
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      files: ['formfuzzer.js']
    }).then(() => {
      // Now run the fuzzer
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: () => {
          if (window.formFuzzer) {
            window.formFuzzer.discoverAndFuzzForms().then(results => {
              console.log('[Lonkero] Form fuzzing complete:', window.formFuzzer.getReport());
              alert(`Form fuzzing complete!\n${results.length} tests run.\nCheck console for details.`);
            }).catch(err => {
              alert('Form fuzzing error: ' + err.message);
            });
          } else {
            alert('Form fuzzer failed to initialize.');
          }
        }
      });
    }).catch(err => {
      console.error('Failed to inject form fuzzer:', err);
      alert('Failed to inject form fuzzer: ' + err.message);
    });
  });
});

// Fuzz GraphQL
document.getElementById('fuzzGraphqlBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_fuzz_graphql');
  // First get discovered endpoints to find GraphQL
  chrome.runtime.sendMessage({ type: 'getEndpoints' }, (endpoints) => {
    const graphqlEndpoints = (endpoints || []).filter(e => e.isGraphQL);

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0].id;

      // Inject GraphQL fuzzer
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        files: ['graphql-fuzzer.js']
      }).then(() => {
        // Run the fuzzer with discovered endpoints
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          world: 'MAIN',
          args: [graphqlEndpoints],
          func: (discoveredEndpoints) => {
            if (window.gqlFuzz) {
              // Pass discovered endpoints to fuzzer
              if (discoveredEndpoints && discoveredEndpoints.length > 0) {
                window.gqlFuzz.discoveredEndpoints = discoveredEndpoints;
              }
              window.gqlFuzz.fuzz().then(results => {
                const report = window.gqlFuzz.getReport();
                console.log('[Lonkero] GraphQL fuzzing complete:', report);
                alert(`GraphQL Fuzzing Complete!\n\nEndpoints tested: ${report.endpointsTested}\nVulnerabilities: ${report.vulnerabilities}\nIntrospection enabled: ${report.findings.filter(f => f.type === 'introspection_enabled').length}\n\nCheck console for details.`);
              }).catch(err => {
                alert('GraphQL fuzzing error: ' + err.message);
              });
            } else {
              alert('GraphQL fuzzer failed to initialize.');
            }
          }
        });
      }).catch(err => {
        console.error('Failed to inject GraphQL fuzzer:', err);
        alert('Failed to inject GraphQL fuzzer: ' + err.message);
      });
    });
  });
});

// XSS Scan
document.getElementById('xssScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_xss_scan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    // Inject XSS scanner and run full scan
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      files: ['xss-scanner.js']
    }).then(() => {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: () => {
          if (window.xssScanner) {
            // Run comprehensive scan
            window.xssScanner.scan().then(results => {
              console.log('[Lonkero] XSS scan complete:', results);
              const vulnCount = results.length;
              const domXss = results.filter(r => r.type === 'DOM_XSS' || r.type === 'DOM_XSS_POTENTIAL').length;
              const reflected = results.filter(r => r.type === 'REFLECTED_XSS').length;
              alert(`XSS Scan Complete!\n\n${vulnCount} vulnerabilities found:\n- ${domXss} DOM XSS\n- ${reflected} Reflected XSS\n\nCheck console & Findings tab for details.`);
            }).catch(err => {
              alert('XSS scan error: ' + err.message);
            });
          } else {
            alert('XSS scanner failed to initialize.');
          }
        }
      });
    }).catch(err => {
      console.error('Failed to inject XSS scanner:', err);
      alert('Failed to inject XSS scanner: ' + err.message);
    });
  });
});

// Deep XSS Scan (Crawl + Test ALL endpoints)
document.getElementById('deepXssScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_deep_xss_scan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    alert('Starting Deep XSS Scan...\nThis will crawl the site and test ALL discovered endpoints.\nThis may take a while. Check console for progress.');

    // Inject XSS scanner and run deep scan
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      files: ['xss-scanner.js']
    }).then(() => {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: () => {
          if (window.xssScanner) {
            // Run deep scan with crawler
            window.xssScanner.deepScan({ maxDepth: 2, maxPages: 100 }).then(result => {
              console.log('[Lonkero] Deep XSS scan complete:', result);
              const vulnCount = result.findings.length;
              const domXss = result.findings.filter(r => r.type === 'DOM_XSS' || r.type === 'DOM_XSS_POTENTIAL').length;
              const reflected = result.findings.filter(r => r.type === 'REFLECTED_XSS').length;
              alert(`Deep XSS Scan Complete!\n\nEndpoints crawled: ${result.stats.endpointsCrawled}\nParameters tested: ${result.stats.paramsTested}\n\n${vulnCount} vulnerabilities found:\n- ${domXss} DOM XSS\n- ${reflected} Reflected XSS\n\nCheck console & Findings tab for details.`);
            }).catch(err => {
              alert('Deep XSS scan error: ' + err.message);
            });
          } else {
            alert('XSS scanner failed to initialize.');
          }
        }
      });
    }).catch(err => {
      console.error('Failed to inject XSS scanner:', err);
      alert('Failed to inject XSS scanner: ' + err.message);
    });
  });
});

// SQLi Scan
document.getElementById('sqliScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_sqli_scan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    // Inject SQLi scanner and run scan
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      files: ['sql-scanner.js']
    }).then(() => {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: () => {
          if (window.sqlScanner) {
            window.sqlScanner.scan().then(results => {
              console.log('[Lonkero] SQLi scan complete:', results);
              const critical = results.filter(r => r.severity === 'critical').length;
              const high = results.filter(r => r.severity === 'high').length;
              const errorBased = results.filter(r => r.subtype === 'ERROR_BASED').length;
              const booleanBased = results.filter(r => r.subtype === 'BOOLEAN_BASED').length;
              const timeBased = results.filter(r => r.subtype === 'TIME_BASED').length;
              alert(`SQLi Scan Complete!\n\n${results.length} vulnerabilities found:\n- ${critical} Critical (error-based)\n- ${high} High (boolean/time-based)\n\nTypes:\n- ${errorBased} Error-based\n- ${booleanBased} Boolean-based\n- ${timeBased} Time-based\n\nCheck console & Findings tab for details.`);
            }).catch(err => {
              alert('SQLi scan error: ' + err.message);
            });
          } else {
            alert('SQLi scanner failed to initialize.');
          }
        }
      });
    }).catch(err => {
      console.error('Failed to inject SQLi scanner:', err);
      alert('Failed to inject SQLi scanner: ' + err.message);
    });
  });
});

// Deep SQLi Scan (includes time-based)
document.getElementById('deepSqliScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_deep_sqli_scan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    alert('Starting Deep SQLi Scan...\nThis includes time-based detection which is slower.\nCheck console for progress.');

    chrome.scripting.executeScript({
      target: { tabId: tabId },
      world: 'MAIN',
      files: ['sql-scanner.js']
    }).then(() => {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: () => {
          if (window.sqlScanner) {
            window.sqlScanner.deepScan().then(results => {
              console.log('[Lonkero] Deep SQLi scan complete:', results);
              const critical = results.filter(r => r.severity === 'critical').length;
              const high = results.filter(r => r.severity === 'high').length;
              alert(`Deep SQLi Scan Complete!\n\n${results.length} vulnerabilities found:\n- ${critical} Critical\n- ${high} High\n\nCheck console & Findings tab for details.`);
            }).catch(err => {
              alert('Deep SQLi scan error: ' + err.message);
            });
          } else {
            alert('SQLi scanner failed to initialize.');
          }
        }
      });
    }).catch(err => {
      console.error('Failed to inject SQLi scanner:', err);
      alert('Failed to inject SQLi scanner: ' + err.message);
    });
  });
});

// CMS/Framework Scan
document.getElementById('cmsScanBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_cms_scan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0].id;

    // Inject CMS scanner and framework scanner
    Promise.all([
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        files: ['cms-scanner.js']
      }),
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        files: ['framework-scanner.js']
      })
    ]).then(() => {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'MAIN',
        func: async () => {
          const results = [];

          // Run CMS scanner if available
          if (window.cmsScanner) {
            try {
              const cmsReport = await window.cmsScanner.scan();
              // scan() returns a report object with findings property
              if (cmsReport && cmsReport.findings) {
                results.push(...cmsReport.findings);
              }
            } catch (e) {
              console.error('[Lonkero] CMS scan error:', e);
            }
          }

          // Run Framework scanner if available
          if (window.frameworkScanner) {
            try {
              const fwReport = await window.frameworkScanner.scan();
              // scan() returns a report object with findings property
              if (fwReport && fwReport.findings) {
                results.push(...fwReport.findings);
              }
            } catch (e) {
              console.error('[Lonkero] Framework scan error:', e);
            }
          }

          console.log('[Lonkero] CMS/Framework scan complete:', results);

          const cmsCount = results.filter(r => r.category === 'cms' || r.type?.includes('WordPress') || r.type?.includes('Drupal') || r.type?.includes('Joomla')).length;
          const fwCount = results.filter(r => r.category === 'framework' || r.type?.includes('Next') || r.type?.includes('Spring') || r.type?.includes('ASP')).length;
          const vulnCount = results.filter(r => r.severity === 'critical' || r.severity === 'high').length;

          alert(`CMS/Framework Scan Complete!\n\n${results.length} findings:\n- ${vulnCount} critical/high severity\n- ${cmsCount} CMS issues\n- ${fwCount} framework issues\n\nCheck console & Findings tab for details.`);
        }
      });
    }).catch(err => {
      console.error('Failed to inject CMS/Framework scanner:', err);
      alert('Failed to inject scanner: ' + err.message);
    });
  });
});

// Pause/Resume
document.getElementById('pauseBtn')?.addEventListener('click', () => {
  if (currentState?.paused) {
    _t('btn_resume');
    chrome.runtime.sendMessage({ type: 'resume' }, () => setTimeout(refreshState, 100));
  } else {
    _t('btn_pause');
    chrome.runtime.sendMessage({ type: 'pause' }, () => setTimeout(refreshState, 100));
  }
});

// Clear Data
document.getElementById('clearBtn')?.addEventListener('click', () => {
  if (confirm('Clear all findings, endpoints, and captured data?')) {
    _t('btn_clear_data');
    chrome.runtime.sendMessage({ type: 'clearData' }, () => {
      loadFindings();
      loadSecrets();
      loadEndpoints();
      loadRequests();
      refreshState();
    });
  }
});

// Export buttons
document.getElementById('exportFindingsBtn')?.addEventListener('click', () => {
  _t('btn_export', { type: 'findings' });
  chrome.runtime.sendMessage({ type: 'exportFindings' }, (response) => {
    if (response) {
      downloadFile(JSON.stringify(response, null, 2), `lonkero-findings-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportSecretsBtn')?.addEventListener('click', () => {
  _t('btn_export', { type: 'secrets' });
  chrome.runtime.sendMessage({ type: 'getSecrets' }, (secrets) => {
    if (secrets) {
      downloadFile(JSON.stringify(secrets, null, 2), `lonkero-secrets-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportEndpointsBtn')?.addEventListener('click', () => {
  _t('btn_export', { type: 'endpoints' });
  chrome.runtime.sendMessage({ type: 'getEndpoints' }, (endpoints) => {
    if (endpoints) {
      downloadFile(JSON.stringify(endpoints, null, 2), `lonkero-endpoints-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportRequestsBtn')?.addEventListener('click', () => {
  _t('btn_export', { type: 'requests' });
  chrome.runtime.sendMessage({ type: 'getCapturedRequests' }, (requests) => {
    if (requests) {
      downloadFile(JSON.stringify(requests, null, 2), `lonkero-requests-${getDateStr()}.json`, 'application/json');
    }
  });
});

// Request Editor
document.getElementById('newRequestBtn')?.addEventListener('click', () => {
  document.getElementById('editorMethod').value = 'GET';
  document.getElementById('editorUrl').value = '';
  document.getElementById('editorHeaders').value = '{}';
  document.getElementById('editorBody').value = '';
  document.getElementById('requestEditor').classList.add('active');
});

document.getElementById('closeEditorBtn')?.addEventListener('click', () => {
  document.getElementById('requestEditor').classList.remove('active');
});

document.getElementById('sendRequestBtn')?.addEventListener('click', () => {
  if (!requireLicense()) return;
  _t('btn_send_request');
  const method = document.getElementById('editorMethod').value;
  const url = document.getElementById('editorUrl').value;
  let headers = {};

  try {
    headers = JSON.parse(document.getElementById('editorHeaders').value || '{}');
  } catch (e) {
    alert('Invalid JSON in headers');
    return;
  }

  const body = document.getElementById('editorBody').value || undefined;

  if (!url) {
    alert('Please enter a URL');
    return;
  }

  // Show loading state
  const responseViewer = document.getElementById('responseViewer');
  const responseStatus = document.getElementById('responseStatus');
  const responseHeadersView = document.getElementById('responseHeadersView');
  const responseBody = document.getElementById('responseBody');

  responseViewer.style.display = 'block';
  responseStatus.textContent = 'Loading...';
  responseStatus.style.color = '#ffaa00';
  responseHeadersView.textContent = '';
  responseBody.value = '';

  chrome.runtime.sendMessage({
    type: 'replayRequest',
    request: { method, url, headers, body }
  }, (response) => {
    if (response?.error) {
      responseStatus.textContent = 'Error: ' + response.error;
      responseStatus.style.color = '#ff3939';
    } else {
      // Show status with color coding
      const statusColor = response.status < 300 ? '#39ff14' : response.status < 400 ? '#00aaff' : response.status < 500 ? '#ffaa00' : '#ff3939';
      responseStatus.textContent = `${response.status} ${response.statusText}`;
      responseStatus.style.color = statusColor;

      // Show headers
      const headerLines = Object.entries(response.headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      responseHeadersView.textContent = headerLines;

      // Show body (try to pretty-print JSON)
      let bodyText = response.body || '';
      try {
        const parsed = JSON.parse(bodyText);
        bodyText = JSON.stringify(parsed, null, 2);
      } catch (e) {
        // Not JSON, show as-is
      }
      responseBody.value = bodyText;

      console.log('[Lonkero] Response:', response);
    }
  });
});

// Copy response to clipboard
document.getElementById('copyResponseBtn')?.addEventListener('click', () => {
  const responseBody = document.getElementById('responseBody');
  navigator.clipboard.writeText(responseBody.value).then(() => {
    const btn = document.getElementById('copyResponseBtn');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
});

// ============================================================
// UTILITIES
// ============================================================

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

function downloadFile(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function getDateStr() {
  return new Date().toISOString().split('T')[0];
}

// ============================================================
// ANALYTICS TRACKING
// ============================================================

/**
 * Track extension usage via lonkero.bountyy.fi
 * Only fires once per session and requires consent
 */
function trackUsage() {
  // Require explicit consent to track
  if (!checkConsentAccepted()) return;

  const sessionKey = 'lonkero_ext_tracked';

  // Only track once per browser session
  if (sessionStorage.getItem(sessionKey)) return;

  try {
    const version = chrome.runtime.getManifest().version;

    fetch('https://lonkero.bountyy.fi/t', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        p: '/extension',
        v: version
      })
    }).catch(() => {});

    sessionStorage.setItem(sessionKey, '1');
  } catch (e) {
    // Silently fail
  }
}

// ============================================================
// INITIALIZATION
// ============================================================

// Show consent modal if user hasn't answered yet
if (!checkConsentAnswered()) {
  showConsentModal();
} else if (checkConsentAccepted()) {
  // User already consented, track usage
  trackUsage();
}
// If declined, we just continue without tracking

// Check license first, then load state
checkLicenseState();
refreshState();
loadFindings();
loadTechnologies();
_t('popup_opened');

setInterval(() => {
  refreshState();
  loadTechnologies();
  // Periodically re-check license (picks up CLI-validated or newly entered keys)
  if (!isExtensionLicensed) checkLicenseState();
}, 1000);
