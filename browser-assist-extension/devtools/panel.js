// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero DevTools Panel
 * Professional security testing interface with:
 * - Proxy (request/response capture)
 * - Scanner (vulnerability scanning)
 * - Findings (results viewer)
 * - Intruder (payload fuzzing)
 * - Repeater (request replay)
 */

class LonkeroPanel {
  constructor() {
    this.requests = [];
    this.findings = [];
    this.selectedRequest = null;
    this.selectedFinding = null;
    this.connected = false;
    this.scanning = false;
    this.scanStartTime = null;
    this.repeaterTabs = new Map();
    this.repeaterCounter = 1;

    this.init();
  }

  init() {
    this.setupTabs();
    this.setupProxy();
    this.setupScanner();
    this.setupFindings();
    this.setupIntruder();
    this.setupRepeater();
    this.connectToBackground();
    this.loadState();

    console.log('[Lonkero DevTools] Panel initialized');
  }

  // ============================================================
  // TAB NAVIGATION
  // ============================================================

  setupTabs() {
    document.querySelectorAll('.tabs .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const tabId = tab.dataset.tab;

        document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        document.getElementById(`panel-${tabId}`).classList.add('active');
      });
    });
  }

  // ============================================================
  // BACKGROUND CONNECTION
  // ============================================================

  connectToBackground() {
    // Get initial state
    chrome.runtime.sendMessage({ type: 'getState' }, (state) => {
      if (chrome.runtime.lastError) {
        console.error('[Lonkero] Background connection error:', chrome.runtime.lastError);
        return;
      }

      if (state) {
        this.connected = state.connected;
        this.updateConnectionStatus();
        this.requests = state.capturedRequests || [];
        this.findings = state.findings || [];
        this.renderRequestList();
        this.renderFindings();
        this.updateFindingsCounts();
      }
    });

    // Listen for messages from background
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      switch (msg.type) {
        case 'connectionChange':
          this.connected = msg.connected;
          this.updateConnectionStatus();
          break;

        case 'newRequest':
          this.addRequest(msg.request);
          break;

        case 'newFinding':
          this.addFinding(msg.finding);
          break;

        case 'scanProgress':
          this.updateScanProgress(msg);
          break;

        case 'scanComplete':
          this.onScanComplete();
          break;

        case 'cliMessage':
          this.handleCLIMessage(msg.data);
          break;
      }
    });

    // Connection button
    document.getElementById('btnConnect').addEventListener('click', () => {
      if (this.connected) {
        chrome.runtime.sendMessage({ type: 'disconnect' });
      } else {
        chrome.runtime.sendMessage({ type: 'reconnect' });
      }
    });
  }

  updateConnectionStatus() {
    const statusEl = document.getElementById('connectionStatus');
    const dot = statusEl.querySelector('.status-dot');
    const text = statusEl.querySelector('.status-text');
    const btn = document.getElementById('btnConnect');
    const cliInfo = document.getElementById('cliInfo');

    if (this.connected) {
      dot.classList.add('connected');
      text.textContent = 'Connected';
      btn.textContent = 'Disconnect';
      cliInfo.textContent = 'CLI: Connected';
    } else {
      dot.classList.remove('connected');
      text.textContent = 'Disconnected';
      btn.textContent = 'Connect';
      cliInfo.textContent = 'CLI: Not connected';
    }
  }

  handleCLIMessage(data) {
    // Handle messages from CLI
    switch (data.type) {
      case 'finding':
        this.addFinding(data.finding);
        // Forward to content script for highlighting
        this.highlightFinding(data.finding);
        break;

      case 'progress':
        this.updateScanProgress(data);
        break;

      case 'tech_detected':
        this.setStatus(`Tech detected: ${data.technologies.join(', ')}`);
        break;

      case 'param_risk':
        this.highlightRiskyParams(data.parameters);
        break;
    }
  }

  loadState() {
    chrome.storage.local.get(['findings', 'scope'], (result) => {
      if (result.findings) {
        this.findings = result.findings;
        this.renderFindings();
        this.updateFindingsCounts();
      }
      if (result.scope) {
        result.scope.forEach(pattern => this.addScopeItem(pattern));
      }
    });
  }

  // ============================================================
  // PROXY TAB
  // ============================================================

  setupProxy() {
    // Filter
    document.getElementById('proxyFilter').addEventListener('input', (e) => {
      this.filterRequests(e.target.value);
    });

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.filterRequests(document.getElementById('proxyFilter').value, btn.dataset.filter);
      });
    });

    // Clear
    document.getElementById('btnClearProxy').addEventListener('click', () => {
      this.requests = [];
      this.renderRequestList();
      chrome.runtime.sendMessage({ type: 'clearRequests' });
    });

    // Export HAR
    document.getElementById('btnExportHAR').addEventListener('click', () => {
      this.exportHAR();
    });

    // Detail tabs
    document.querySelectorAll('.detail-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const detail = tab.dataset.detail;
        document.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.detail-pane').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`detail-${detail}`).classList.add('active');
      });
    });

    // Action buttons
    document.getElementById('btnSendToScanner').addEventListener('click', () => {
      if (this.selectedRequest) this.sendToScanner(this.selectedRequest);
    });

    document.getElementById('btnSendToIntruder').addEventListener('click', () => {
      if (this.selectedRequest) this.sendToIntruder(this.selectedRequest);
    });

    document.getElementById('btnSendToRepeater').addEventListener('click', () => {
      if (this.selectedRequest) this.sendToRepeater(this.selectedRequest);
    });

    document.getElementById('btnCopyAsCurl').addEventListener('click', () => {
      if (this.selectedRequest) this.copyAsCurl(this.selectedRequest);
    });
  }

  addRequest(request) {
    this.requests.unshift(request);
    if (this.requests.length > 1000) {
      this.requests = this.requests.slice(0, 1000);
    }
    this.renderRequestList();
  }

  renderRequestList(filter = '', filterType = 'all') {
    const list = document.getElementById('requestList');
    let filtered = this.requests;

    if (filter) {
      const f = filter.toLowerCase();
      filtered = filtered.filter(r => r.url.toLowerCase().includes(f));
    }

    if (filterType !== 'all') {
      filtered = filtered.filter(r => {
        if (filterType === 'xhr') return r.type === 'xhr' || r.type === 'fetch';
        if (filterType === 'form') return r.method === 'POST' && r.contentType?.includes('form');
        if (filterType === 'graphql') return r.url.includes('graphql');
        return true;
      });
    }

    if (filtered.length === 0) {
      list.innerHTML = '<div class="empty-state">No requests captured yet</div>';
      return;
    }

    list.innerHTML = filtered.map((req, i) => `
      <div class="request-item ${req.hasFinding ? 'has-finding' : ''}" data-index="${i}">
        <span class="method method-${(req.method || 'GET').toLowerCase()}">${req.method || 'GET'}</span>
        <span class="request-url">${this.truncateUrl(req.url)}</span>
        <span class="request-status status-${Math.floor((req.status || 0) / 100)}xx">${req.status || '-'}</span>
        <span class="request-time">${req.duration ? req.duration + 'ms' : '-'}</span>
      </div>
    `).join('');

    list.querySelectorAll('.request-item').forEach(item => {
      item.addEventListener('click', () => {
        const index = parseInt(item.dataset.index);
        this.selectRequest(filtered[index]);
        list.querySelectorAll('.request-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
      });
    });
  }

  filterRequests(filter, type = 'all') {
    this.renderRequestList(filter, type);
  }

  selectRequest(request) {
    this.selectedRequest = request;

    // Raw request
    document.getElementById('requestRaw').textContent = this.formatRawRequest(request);

    // Raw response
    document.getElementById('responseRaw').textContent = request.responseBody || 'No response captured';

    // Params
    const params = this.parseParams(request);
    const paramsBody = document.querySelector('#paramsTable tbody');
    paramsBody.innerHTML = params.map(p => `
      <tr>
        <td>${p.name}</td>
        <td>${this.escapeHtml(p.value)}</td>
        <td style="color: var(--severity-${p.risk})">${p.risk}</td>
      </tr>
    `).join('');

    // Cookies
    const cookies = this.parseCookies(request);
    const cookiesBody = document.querySelector('#cookiesTable tbody');
    cookiesBody.innerHTML = cookies.map(c => `
      <tr>
        <td>${c.name}</td>
        <td>${this.escapeHtml(c.value)}</td>
        <td>${c.flags}</td>
      </tr>
    `).join('');
  }

  formatRawRequest(request) {
    try {
      const url = new URL(request.url);
      let raw = `${request.method || 'GET'} ${url.pathname}${url.search} HTTP/1.1\n`;
      raw += `Host: ${url.host}\n`;

      for (const [key, value] of Object.entries(request.headers || {})) {
        raw += `${key}: ${value}\n`;
      }

      if (request.body) {
        raw += `\n${request.body}`;
      }

      return raw;
    } catch (e) {
      return `${request.method || 'GET'} ${request.url}`;
    }
  }

  parseParams(request) {
    const params = [];
    try {
      const url = new URL(request.url);
      url.searchParams.forEach((value, name) => {
        params.push({ name, value, risk: this.assessRisk(name) });
      });
    } catch (e) {}

    if (request.body) {
      try {
        const bodyParams = new URLSearchParams(request.body);
        bodyParams.forEach((value, name) => {
          params.push({ name, value, risk: this.assessRisk(name) });
        });
      } catch (e) {
        try {
          const json = JSON.parse(request.body);
          Object.entries(json).forEach(([name, value]) => {
            params.push({ name, value: JSON.stringify(value), risk: this.assessRisk(name) });
          });
        } catch (e) {}
      }
    }

    return params;
  }

  parseCookies(request) {
    const cookies = [];
    const cookieHeader = request.headers?.['Cookie'] || request.headers?.['cookie'] || '';

    cookieHeader.split(';').forEach(part => {
      const [name, ...valueParts] = part.trim().split('=');
      if (name) {
        cookies.push({
          name: name.trim(),
          value: valueParts.join('='),
          flags: ''
        });
      }
    });

    return cookies;
  }

  assessRisk(name) {
    const n = name.toLowerCase();
    const high = ['id', 'user', 'admin', 'password', 'token', 'key', 'secret', 'file', 'path', 'cmd', 'exec', 'query', 'sql', 'email'];
    const medium = ['search', 'q', 'url', 'redirect', 'return', 'next', 'callback', 'ref', 'name'];

    if (high.some(h => n.includes(h))) return 'high';
    if (medium.some(m => n.includes(m))) return 'medium';
    return 'low';
  }

  truncateUrl(url) {
    try {
      const parsed = new URL(url);
      const path = parsed.pathname + parsed.search;
      return path.length > 80 ? path.substring(0, 80) + '...' : path;
    } catch {
      return url.length > 80 ? url.substring(0, 80) + '...' : url;
    }
  }

  escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  exportHAR() {
    const har = {
      log: {
        version: '1.2',
        creator: { name: 'Lonkero', version: '3.9' },
        entries: this.requests.map(r => ({
          startedDateTime: new Date(r.timestamp || Date.now()).toISOString(),
          time: r.duration || 0,
          request: {
            method: r.method || 'GET',
            url: r.url,
            headers: Object.entries(r.headers || {}).map(([n, v]) => ({ name: n, value: v })),
            postData: r.body ? { text: r.body } : undefined
          },
          response: {
            status: r.status || 0,
            statusText: r.statusText || '',
            headers: [],
            content: { text: r.responseBody || '' }
          }
        }))
      }
    };

    const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lonkero-capture-${Date.now()}.har`;
    a.click();
    URL.revokeObjectURL(url);

    this.setStatus('HAR exported');
  }

  copyAsCurl(request) {
    let curl = `curl -X ${request.method || 'GET'} '${request.url}'`;

    for (const [key, value] of Object.entries(request.headers || {})) {
      curl += ` \\\n  -H '${key}: ${value}'`;
    }

    if (request.body) {
      curl += ` \\\n  -d '${request.body.replace(/'/g, "\\'")}'`;
    }

    navigator.clipboard.writeText(curl);
    this.setStatus('Copied as cURL');
  }

  // ============================================================
  // SCANNER TAB
  // ============================================================

  setupScanner() {
    document.getElementById('btnAddScope').addEventListener('click', () => {
      const input = document.getElementById('scopeInput');
      if (input.value.trim()) {
        this.addScopeItem(input.value.trim());
        input.value = '';
      }
    });

    document.getElementById('btnStartScan').addEventListener('click', () => this.startScan());
    document.getElementById('btnPauseScan').addEventListener('click', () => this.pauseScan());
    document.getElementById('btnStopScan').addEventListener('click', () => this.stopScan());
  }

  addScopeItem(pattern) {
    const list = document.getElementById('scopeList');
    const item = document.createElement('div');
    item.className = 'scope-item';
    item.innerHTML = `
      <span>${pattern}</span>
      <button class="btn-remove" title="Remove">×</button>
    `;
    item.querySelector('.btn-remove').addEventListener('click', () => {
      item.remove();
      this.saveScope();
    });
    list.appendChild(item);
    this.saveScope();
  }

  saveScope() {
    const patterns = Array.from(document.querySelectorAll('.scope-item span')).map(el => el.textContent);
    chrome.storage.local.set({ scope: patterns });
  }

  getScope() {
    return Array.from(document.querySelectorAll('.scope-item span')).map(el => el.textContent);
  }

  startScan() {
    const scope = this.getScope();
    if (scope.length === 0) {
      this.setStatus('Error: No scope defined');
      return;
    }

    if (!this.connected) {
      this.setStatus('Error: Not connected to CLI');
      return;
    }

    chrome.runtime.sendMessage({
      type: 'startScan',
      scope: scope,
      options: {
        useSession: document.getElementById('optUseSession').checked,
        activeScan: document.getElementById('optActiveScan').checked,
        highlightFindings: document.getElementById('optHighlightFindings').checked,
      }
    });

    this.scanning = true;
    this.scanStartTime = Date.now();

    document.getElementById('btnStartScan').disabled = true;
    document.getElementById('btnPauseScan').disabled = false;
    document.getElementById('btnStopScan').disabled = false;
    document.getElementById('currentActivity').textContent = 'Starting scan...';

    this.updateElapsedTime();
    this.setStatus('Scan started');
  }

  pauseScan() {
    const btn = document.getElementById('btnPauseScan');
    const isPaused = btn.textContent.includes('Resume');

    chrome.runtime.sendMessage({ type: isPaused ? 'resumeScan' : 'pauseScan' });

    btn.innerHTML = isPaused ? '⏸️ Pause' : '▶️ Resume';
    this.setStatus(isPaused ? 'Scan resumed' : 'Scan paused');
  }

  stopScan() {
    chrome.runtime.sendMessage({ type: 'stopScan' });
    this.onScanComplete();
    this.setStatus('Scan stopped');
  }

  onScanComplete() {
    this.scanning = false;
    document.getElementById('btnStartScan').disabled = false;
    document.getElementById('btnPauseScan').disabled = true;
    document.getElementById('btnStopScan').disabled = true;
    document.getElementById('btnPauseScan').innerHTML = '⏸️ Pause';
    document.getElementById('currentActivity').textContent = 'Scan complete';

    // Notify content script
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'scan_complete' });
      }
    });
  }

  updateScanProgress(progress) {
    document.getElementById('progressFill').style.width = `${progress.percent || 0}%`;
    document.getElementById('progressText').textContent = `${progress.percent || 0}%`;
    document.getElementById('statRequests').textContent = progress.requests || 0;
    document.getElementById('statFindings').textContent = progress.findings || this.findings.length;
    document.getElementById('currentActivity').textContent = progress.scanner || progress.phase || 'Scanning...';

    // Update content script
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'scan_progress',
          scanner: progress.scanner,
          percent: progress.percent
        });
      }
    });
  }

  updateElapsedTime() {
    if (!this.scanning) return;

    const elapsed = Math.floor((Date.now() - this.scanStartTime) / 1000);
    const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
    const secs = (elapsed % 60).toString().padStart(2, '0');
    document.getElementById('statElapsed').textContent = `${mins}:${secs}`;

    setTimeout(() => this.updateElapsedTime(), 1000);
  }

  // ============================================================
  // FINDINGS TAB
  // ============================================================

  setupFindings() {
    document.querySelectorAll('.severity-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        btn.classList.toggle('active');
        this.renderFindings();
      });
    });

    document.getElementById('btnExportFindings').addEventListener('click', () => {
      this.exportFindings();
    });

    document.getElementById('btnClearFindings').addEventListener('click', () => {
      this.findings = [];
      this.renderFindings();
      this.updateFindingsCounts();
      chrome.storage.local.remove('findings');
      this.setStatus('Findings cleared');
    });
  }

  addFinding(finding) {
    // Dedupe
    const key = `${finding.vuln_type || finding.type}:${finding.url}:${finding.parameter}`;
    if (this.findings.some(f => `${f.vuln_type || f.type}:${f.url}:${f.parameter}` === key)) {
      return;
    }

    this.findings.unshift(finding);
    this.renderFindings();
    this.updateFindingsCounts();

    // Save
    chrome.storage.local.set({ findings: this.findings.slice(0, 500) });

    // Highlight if option enabled
    if (document.getElementById('optHighlightFindings')?.checked) {
      this.highlightFinding(finding);
    }
  }

  renderFindings() {
    const activeSeverities = Array.from(document.querySelectorAll('.severity-btn.active'))
      .map(btn => btn.dataset.severity);

    const filtered = this.findings.filter(f => {
      const sev = (f.severity || 'medium').toLowerCase();
      return activeSeverities.includes(sev);
    });

    const list = document.getElementById('findingsList');

    if (filtered.length === 0) {
      list.innerHTML = '<div class="empty-state">No findings yet</div>';
      return;
    }

    list.innerHTML = filtered.map((f, i) => {
      const sev = (f.severity || 'medium').toLowerCase();
      return `
        <div class="finding-item ${sev}" data-index="${i}">
          <div class="finding-header">
            <span class="finding-severity ${sev}">${f.severity || 'Medium'}</span>
            <span class="finding-type">${f.vuln_type || f.type || 'Vulnerability'}</span>
          </div>
          <div class="finding-url">${f.url || '-'}</div>
        </div>
      `;
    }).join('');

    list.querySelectorAll('.finding-item').forEach(item => {
      item.addEventListener('click', () => {
        const index = parseInt(item.dataset.index);
        this.selectFinding(filtered[index]);
        list.querySelectorAll('.finding-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
      });
    });
  }

  selectFinding(finding) {
    this.selectedFinding = finding;
    const detail = document.getElementById('findingDetail');

    const sev = (finding.severity || 'medium').toLowerCase();

    detail.innerHTML = `
      <div class="finding-header">
        <span class="finding-severity ${sev}">${finding.severity || 'Medium'}</span>
        <span class="finding-type">${finding.vuln_type || finding.type || 'Vulnerability'}</span>
      </div>

      <h4 style="margin-top: 16px;">URL</h4>
      <code style="display: block; padding: 8px; background: var(--bg-tertiary); border-radius: 4px; word-break: break-all;">
        ${this.escapeHtml(finding.url || '-')}
      </code>

      <h4 style="margin-top: 16px;">Parameter</h4>
      <code style="display: block; padding: 8px; background: var(--bg-tertiary); border-radius: 4px;">
        ${this.escapeHtml(finding.parameter || '-')}
      </code>

      ${finding.payload ? `
        <h4 style="margin-top: 16px;">Payload</h4>
        <code style="display: block; padding: 8px; background: var(--bg-tertiary); border-radius: 4px; word-break: break-all;">
          ${this.escapeHtml(finding.payload)}
        </code>
      ` : ''}

      ${finding.evidence ? `
        <h4 style="margin-top: 16px;">Evidence</h4>
        <pre style="padding: 8px; background: var(--bg-tertiary); border-radius: 4px; overflow: auto; max-height: 200px; white-space: pre-wrap;">
${this.escapeHtml(finding.evidence)}</pre>
      ` : ''}

      ${finding.description ? `
        <h4 style="margin-top: 16px;">Description</h4>
        <p style="color: var(--text-secondary);">${this.escapeHtml(finding.description)}</p>
      ` : ''}

      ${finding.remediation ? `
        <h4 style="margin-top: 16px;">Remediation</h4>
        <p style="color: var(--text-secondary);">${this.escapeHtml(finding.remediation.substring(0, 500))}</p>
      ` : ''}

      <div style="margin-top: 16px; display: flex; gap: 8px;">
        <button class="btn btn-sm" onclick="lonkeroPanel.highlightFinding(lonkeroPanel.selectedFinding)">
          Highlight in Page
        </button>
        <button class="btn btn-sm" onclick="lonkeroPanel.copyFinding(lonkeroPanel.selectedFinding)">
          Copy JSON
        </button>
      </div>
    `;
  }

  updateFindingsCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };

    this.findings.forEach(f => {
      const sev = (f.severity || 'medium').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });

    document.getElementById('countCritical').textContent = counts.critical;
    document.getElementById('countHigh').textContent = counts.high;
    document.getElementById('countMedium').textContent = counts.medium;
    document.getElementById('countLow').textContent = counts.low;

    const total = counts.critical + counts.high + counts.medium + counts.low;
    document.getElementById('findingsBadge').textContent = total;
    document.getElementById('findingsBadge').style.display = total > 0 ? 'inline-flex' : 'none';
  }

  highlightFinding(finding) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'highlight_finding',
          finding: finding
        });
      }
    });
  }

  highlightRiskyParams(params) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'highlight_params',
          parameters: params
        });
      }
    });
  }

  copyFinding(finding) {
    navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
    this.setStatus('Finding copied');
  }

  exportFindings() {
    const data = JSON.stringify(this.findings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lonkero-findings-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this.setStatus('Findings exported');
  }

  // ============================================================
  // INTRUDER TAB
  // ============================================================

  setupIntruder() {
    document.getElementById('btnAddMarker').addEventListener('click', () => {
      const editor = document.getElementById('intruderTemplate');
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      const text = editor.value;
      editor.value = text.substring(0, start) + '§' + text.substring(start, end) + '§' + text.substring(end);
      editor.focus();
    });

    document.getElementById('btnClearMarkers').addEventListener('click', () => {
      const editor = document.getElementById('intruderTemplate');
      editor.value = editor.value.replace(/§/g, '');
    });

    document.getElementById('btnAutoMark').addEventListener('click', () => {
      this.autoMarkParams();
    });

    document.getElementById('btnStartAttack').addEventListener('click', () => {
      this.startIntruderAttack();
    });
  }

  autoMarkParams() {
    const editor = document.getElementById('intruderTemplate');
    let text = editor.value;

    // Mark URL params
    text = text.replace(/=([^&\s§]+)/g, '=§$1§');

    // Mark JSON values
    text = text.replace(/":\s*"([^"§]+)"/g, '": "§$1§"');
    text = text.replace(/":\s*(\d+)/g, '": §$1§');

    editor.value = text;
  }

  startIntruderAttack() {
    const template = document.getElementById('intruderTemplate').value;
    const payloadType = document.getElementById('payloadSet').value;
    let payloads = [];

    if (payloadType === 'custom') {
      payloads = document.getElementById('customPayloads').value.split('\n').filter(p => p.trim());
    } else {
      payloads = this.getBuiltinPayloads(payloadType);
    }

    if (payloads.length === 0) {
      this.setStatus('Error: No payloads defined');
      return;
    }

    if (!template.includes('§')) {
      this.setStatus('Error: No injection points marked with §');
      return;
    }

    chrome.runtime.sendMessage({
      type: 'intruderAttack',
      template: template,
      payloads: payloads
    }, (results) => {
      if (results) {
        this.renderIntruderResults(results);
      }
    });

    this.setStatus(`Attack started with ${payloads.length} payloads`);
  }

  getBuiltinPayloads(type) {
    const payloads = {
      numbers: Array.from({ length: 1000 }, (_, i) => String(i + 1)),
      sqli: ["'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"", "1' AND '1'='1", "admin'--", "' UNION SELECT NULL--", "1; DROP TABLE users--"],
      xss: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>", "javascript:alert(1)", "<svg onload=alert(1)>", "'-alert(1)-'"],
      traversal: ["../", "..\\", "....//", "..%2f", "%2e%2e/", "..%252f", "/etc/passwd", "C:\\Windows\\win.ini"],
      ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}", "{{constructor.constructor('return this')()}}"]
    };
    return payloads[type] || [];
  }

  renderIntruderResults(results) {
    const tbody = document.querySelector('#intruderResults tbody');
    tbody.innerHTML = results.map((r, i) => `
      <tr class="${r.interesting ? 'interesting' : ''}">
        <td>${i + 1}</td>
        <td>${this.escapeHtml(r.payload)}</td>
        <td class="status-${Math.floor(r.status / 100)}xx">${r.status}</td>
        <td>${r.length}</td>
        <td>${r.time}ms</td>
        <td>${r.diff || '-'}</td>
      </tr>
    `).join('');
  }

  // ============================================================
  // REPEATER TAB
  // ============================================================

  setupRepeater() {
    document.getElementById('btnNewRepeater').addEventListener('click', () => {
      this.addRepeaterTab();
    });

    document.getElementById('btnSendRequest').addEventListener('click', () => {
      this.sendRepeaterRequest();
    });

    // Response view tabs
    document.querySelectorAll('.resp-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.resp-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        const view = tab.dataset.view;
        if (view === 'render') {
          document.getElementById('repeaterResponse').style.display = 'none';
          document.getElementById('repeaterRender').style.display = 'block';
        } else {
          document.getElementById('repeaterResponse').style.display = 'block';
          document.getElementById('repeaterRender').style.display = 'none';
        }
      });
    });
  }

  addRepeaterTab() {
    this.repeaterCounter++;
    const tabs = document.getElementById('repeaterTabs');
    const tab = document.createElement('button');
    tab.className = 'repeater-tab';
    tab.dataset.id = this.repeaterCounter;
    tab.textContent = `Request ${this.repeaterCounter}`;
    tabs.appendChild(tab);
  }

  sendToRepeater(request) {
    document.querySelector('[data-tab="repeater"]').click();
    document.getElementById('repeaterRequest').value = this.formatRawRequest(request);
  }

  sendRepeaterRequest() {
    const raw = document.getElementById('repeaterRequest').value;
    const request = this.parseRawRequest(raw);

    chrome.runtime.sendMessage({
      type: 'repeaterRequest',
      request: request
    }, (response) => {
      if (response) {
        document.getElementById('respStatus').textContent = `${response.status} ${response.statusText || ''}`;
        document.getElementById('respTime').textContent = `${response.duration || 0}ms`;
        document.getElementById('respSize').textContent = `${(response.body || '').length} bytes`;
        document.getElementById('repeaterResponse').textContent = response.body || '';

        // Render view
        const iframe = document.getElementById('repeaterRender');
        iframe.srcdoc = response.body || '';
      }
    });
  }

  parseRawRequest(raw) {
    const lines = raw.split('\n');
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
        const key = lines[i].substring(0, colonIndex).trim();
        const value = lines[i].substring(colonIndex + 1).trim();
        headers[key] = value;
      }
    }

    const body = bodyStart > 0 ? lines.slice(bodyStart).join('\n') : undefined;
    const host = headers['Host'] || headers['host'] || 'localhost';
    const url = path.startsWith('http') ? path : `https://${host}${path}`;

    return { method, url, headers, body };
  }

  sendToScanner(request) {
    chrome.runtime.sendMessage({
      type: 'scanRequest',
      request: request
    });
    this.setStatus('Sent to scanner');
  }

  sendToIntruder(request) {
    document.querySelector('[data-tab="intruder"]').click();
    document.getElementById('intruderTemplate').value = this.formatRawRequest(request);
    this.setStatus('Sent to Intruder');
  }

  // ============================================================
  // UTILITIES
  // ============================================================

  setStatus(message) {
    document.getElementById('statusMessage').textContent = message;
    console.log('[Lonkero]', message);
  }

  onPanelShown() {
    // Refresh state when panel becomes visible
    chrome.runtime.sendMessage({ type: 'getState' }, (state) => {
      if (state) {
        this.connected = state.connected;
        this.updateConnectionStatus();
      }
    });
  }
}

// Initialize panel
document.addEventListener('DOMContentLoaded', () => {
  window.lonkeroPanel = new LonkeroPanel();
});
