/**
 * Lonkero Browser-Assist Popup UI
 * Full security testing dashboard with request editor/replayer
 */

let currentState = null;
let capturedRequests = [];

// ============================================================
// TAB NAVIGATION
// ============================================================

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const tabName = tab.dataset.tab;

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
    startBtn.textContent = '⏹ Stop Monitoring';
    startBtn.className = 'btn btn-danger';
  } else {
    startBtn.textContent = '▶ Start Monitoring';
    startBtn.className = 'btn btn-primary';
  }

  pauseBtn.textContent = state.paused ? '▶ Resume' : '⏸ Pause';
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
// FINDINGS TAB
// ============================================================

function loadFindings() {
  chrome.runtime.sendMessage({ type: 'getFindings' }, (findings) => {
    const container = document.getElementById('findingsList');
    if (!container) return;

    if (!findings || findings.length === 0) {
      container.innerHTML = '<div class="empty-state">No findings yet. Browse the target site to detect vulnerabilities.</div>';
      return;
    }

    container.innerHTML = findings.map(f => {
      const severity = getSeverity(f.type);
      return `
        <div class="item ${severity}">
          <div class="item-header">
            <span class="item-type">${escapeHtml(f.type)}</span>
          </div>
          <div class="item-url">${escapeHtml(f.url || f.tabUrl || 'Unknown')}</div>
          ${f.evidence ? `<div class="item-detail">${escapeHtml(f.evidence)}</div>` : ''}
        </div>
      `;
    }).join('');
  });
}

function getSeverity(type) {
  const severities = {
    'DOM_XSS_SINK': 'critical',
    'DOM_XSS_SOURCE': 'high',
    'DOM_XSS_POTENTIAL': 'high',
    'PROTOTYPE_POLLUTION': 'critical',
    'SECRET_EXPOSED': 'critical',
    'DANGEROUS_EVAL': 'medium',
    'XSS': 'critical',
    'SQLi': 'critical',
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

    container.innerHTML = endpoints.map(e => `
      <div class="item" onclick="loadEndpointToEditor('${escapeHtml(e.method)}', '${escapeHtml(e.url || e.path)}')">
        <div class="item-header">
          <span class="endpoint-method">${escapeHtml(e.method)}</span>
          <span class="endpoint-path">${escapeHtml(e.path)}</span>
          ${e.isApi ? '<span class="endpoint-api">API</span>' : ''}
        </div>
      </div>
    `).join('');
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
      <div class="item" onclick="loadRequestToEditor(${capturedRequests.length - 1 - i})">
        <div class="item-header">
          <span class="item-badge ${r.method?.toLowerCase()}">${r.method || 'GET'}</span>
          <span class="item-type">${r.status || 'Pending'}</span>
        </div>
        <div class="item-url">${escapeHtml(r.url)}</div>
        <div class="item-detail">${r.duration ? r.duration + 'ms' : ''}</div>
      </div>
    `).join('');
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
window.loadRequestToEditor = function(index) {
  const req = capturedRequests[index];
  if (!req) return;

  const editor = document.getElementById('requestEditor');
  if (!editor) return;

  document.getElementById('editorMethod').value = req.method || 'GET';
  document.getElementById('editorUrl').value = req.url || '';
  document.getElementById('editorHeaders').value = JSON.stringify(req.headers || {}, null, 2);
  document.getElementById('editorBody').value = req.body || '';
  editor.classList.add('active');
};

// ============================================================
// BUTTON HANDLERS
// ============================================================

// Start/Stop Monitoring
document.getElementById('startBtn')?.addEventListener('click', () => {
  if (currentState?.monitoring) {
    chrome.runtime.sendMessage({ type: 'stopMonitoring' }, () => setTimeout(refreshState, 100));
  } else {
    chrome.runtime.sendMessage({ type: 'startMonitoring' }, () => setTimeout(refreshState, 100));
  }
});

// Deep Scan
document.getElementById('deepScanBtn')?.addEventListener('click', () => {
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

// Pause/Resume
document.getElementById('pauseBtn')?.addEventListener('click', () => {
  if (currentState?.paused) {
    chrome.runtime.sendMessage({ type: 'resume' }, () => setTimeout(refreshState, 100));
  } else {
    chrome.runtime.sendMessage({ type: 'pause' }, () => setTimeout(refreshState, 100));
  }
});

// Clear Data
document.getElementById('clearBtn')?.addEventListener('click', () => {
  if (confirm('Clear all findings, endpoints, and captured data?')) {
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
  chrome.runtime.sendMessage({ type: 'exportFindings' }, (response) => {
    if (response) {
      downloadFile(JSON.stringify(response, null, 2), `lonkero-findings-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportSecretsBtn')?.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'getSecrets' }, (secrets) => {
    if (secrets) {
      downloadFile(JSON.stringify(secrets, null, 2), `lonkero-secrets-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportEndpointsBtn')?.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'getEndpoints' }, (endpoints) => {
    if (endpoints) {
      downloadFile(JSON.stringify(endpoints, null, 2), `lonkero-endpoints-${getDateStr()}.json`, 'application/json');
    }
  });
});

document.getElementById('exportRequestsBtn')?.addEventListener('click', () => {
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
// INITIALIZATION
// ============================================================

refreshState();
loadFindings();

setInterval(refreshState, 1000);
