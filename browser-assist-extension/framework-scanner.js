// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Framework Security Scanner v1.0
 * Ported from Rust ASP.NET, Spring, and Next.js scanners
 *
 * Detects and tests vulnerabilities in:
 * - ASP.NET Core (Blazor, SignalR, Kestrel, YSOD, config exposure)
 * - Spring Boot (Actuator, H2 Console, Jolokia, Swagger)
 * - Next.js (Middleware bypass CVE-2025-29927, _next/data exposure, Server Actions SSRF)
 */

(function() {
  'use strict';

  // Framework detection config
  const _wr = document.getElementById('__lk_c');
  const _wc = (_wr && _wr.dataset.v) || window[atob('X19sb25rZXJvS2V5')];
  const _wn = _wr ? _wr.dataset.n : null;
  if (!_wc || _wc.charCodeAt(0) !== 76 || _wc.split('-').length !== 5) {
    window.frameworkScanner = { scan: () => Promise.reject(new Error('Not available')) };
    return;
  }
  let _fwReady = true;

  if (window.__lkFW) return;
  window.__lkFW = true;

  const findings = [];

  // ============================================
  // CVE DATABASES
  // ============================================

  const ASPNET_CVES = [
    { cve: 'CVE-2024-43498', versions: '.NET 9.0.0', severity: 'critical', desc: 'RCE in NrbfDecoder' },
    { cve: 'CVE-2024-38229', versions: '.NET 8.0.x, 9.0.0-preview', severity: 'critical', desc: 'RCE in Kestrel HTTP/3' },
    { cve: 'CVE-2024-35264', versions: '.NET 8.0.x', severity: 'critical', desc: 'RCE in ASP.NET Core' },
    { cve: 'CVE-2023-44487', versions: '.NET 6-8', severity: 'high', desc: 'HTTP/2 Rapid Reset DoS' },
    { cve: 'CVE-2023-33170', versions: '.NET 6.0.x, 7.0.x', severity: 'high', desc: 'Auth bypass' },
  ];

  const NEXTJS_CVES = [
    { cve: 'CVE-2025-29927', versions: '<14.2.25, <15.2.3', severity: 'critical', desc: 'Middleware bypass via x-middleware-subrequest' },
    { cve: 'CVE-2024-34351', versions: '13.4.0-14.1.0', severity: 'critical', desc: 'SSRF in Server Actions' },
    { cve: 'CVE-2024-39693', versions: '<14.2.4', severity: 'high', desc: 'Auth bypass via x-middleware-subrequest' },
    { cve: 'CVE-2024-47831', versions: '<14.2.7', severity: 'high', desc: 'SSRF in image optimization' },
    { cve: 'CVE-2024-51479', versions: '<14.2.18, <15.0.4', severity: 'high', desc: 'Path traversal' },
  ];

  // ============================================
  // FRAMEWORK DETECTION
  // ============================================

  async function detectFrameworks() {
    const detected = {
      aspnet: false,
      aspnetVersion: null,
      spring: false,
      springVersion: null,
      nextjs: false,
      nextjsVersion: null,
    };

    try {
      const resp = await fetch(location.href, { credentials: 'include' });
      const html = await resp.text();
      const headers = {};
      resp.headers.forEach((v, k) => headers[k.toLowerCase()] = v);

      // ASP.NET Detection
      if (headers['x-powered-by']?.toLowerCase().includes('asp.net') ||
          headers['x-aspnet-version'] ||
          headers['x-aspnetcore-version'] ||
          headers['server']?.toLowerCase().includes('kestrel') ||
          html.includes('__VIEWSTATE') ||
          html.includes('_blazor') ||
          html.includes('blazor.webassembly.js') ||
          html.includes('aspnetcore-browser-refresh')) {
        detected.aspnet = true;
        detected.aspnetVersion = headers['x-aspnetcore-version'] || headers['x-aspnet-version'] || 'unknown';
      }

      // Spring Detection
      if (html.includes('Whitelabel Error Page') ||
          html.includes('springframework') ||
          headers['x-application-context']) {
        detected.spring = true;
      }

      // Next.js Detection
      if (html.includes('__NEXT_DATA__') ||
          html.includes('_next/static') ||
          headers['x-powered-by']?.toLowerCase().includes('next.js') ||
          headers['x-nextjs-cache']) {
        detected.nextjs = true;
        // Extract version from __NEXT_DATA__ or headers
        const versionMatch = html.match(/next(?:\.js)?[\/\s]*v?(\d+\.\d+(?:\.\d+)?)/i) ||
                            headers['x-powered-by']?.match(/next\.js?\s*v?(\d+\.\d+(?:\.\d+)?)/i);
        if (versionMatch) detected.nextjsVersion = versionMatch[1];
      }

    } catch (e) {
      console.log('[Framework Scanner] Detection error:', e.message);
    }

    return detected;
  }

  // ============================================
  // ASP.NET SCANNER
  // ============================================

  async function scanASPNET() {
    console.log('[Framework Scanner] Scanning ASP.NET...');
    const vulns = [];
    const base = location.origin;

    // Check YSOD (Yellow Screen of Death) exposure
    const ysodTriggers = [
      '/throw-test-exception',
      '/?__invalid__=<script>',
      '/%00',
      '/web.config',
      '/appsettings.json',
    ];

    for (const trigger of ysodTriggers) {
      try {
        const resp = await fetch(base + trigger, { credentials: 'include' });
        const text = await resp.text();

        const ysodIndicators = [
          'Server Error in',
          'Stack Trace:',
          'System.Web.HttpException',
          'Microsoft.AspNetCore',
          'DeveloperExceptionPageMiddleware',
        ];

        if (ysodIndicators.some(ind => text.includes(ind))) {
          vulns.push({
            type: 'ASPNET_YSOD',
            severity: 'high',
            url: base + trigger,
            description: 'ASP.NET detailed error page (YSOD) exposed',
            evidence: 'Stack trace or exception details visible',
            remediation: 'Set customErrors mode=On or use app.UseExceptionHandler() in production',
          });
          break;
        }
      } catch {}
    }

    // Check Blazor exposure
    const blazorPaths = [
      '/_blazor',
      '/_framework/blazor.server.js',
      '/_framework/blazor.boot.json',
    ];

    for (const path of blazorPaths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok) {
          const text = await resp.text();
          if (path.includes('boot.json') && text.includes('.pdb')) {
            vulns.push({
              type: 'ASPNET_BLAZOR_DEBUG',
              severity: 'medium',
              url: base + path,
              description: 'Blazor debug symbols (PDB) exposed',
              evidence: 'blazor.boot.json contains PDB references',
              remediation: 'Deploy release builds without debug symbols',
            });
          }
        }
      } catch {}
    }

    // Check SignalR exposure
    const signalrPaths = ['/signalr/negotiate', '/chatHub/negotiate', '/_blazor/negotiate'];
    for (const path of signalrPaths) {
      try {
        const resp = await fetch(base + path, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        const text = await resp.text();
        if (text.includes('connectionId') || text.includes('availableTransports')) {
          vulns.push({
            type: 'ASPNET_SIGNALR',
            severity: 'low',
            url: base + path,
            description: 'SignalR hub endpoint exposed',
            evidence: 'Negotiation endpoint accessible',
            remediation: 'Add [Authorize] to hub classes',
          });
          break;
        }
      } catch {}
    }

    // Check config file exposure
    const configPaths = [
      { path: '/web.config', name: 'IIS Config', severity: 'critical' },
      { path: '/appsettings.json', name: 'App Settings', severity: 'critical' },
      { path: '/appsettings.Development.json', name: 'Dev Settings', severity: 'critical' },
      { path: '/.git/config', name: 'Git Config', severity: 'high' },
    ];

    for (const { path, name, severity } of configPaths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok) {
          const text = await resp.text();
          if (text.length > 20 && (text.includes('connectionString') || text.includes('password') ||
              text.includes('{') || text.includes('module'))) {
            vulns.push({
              type: 'ASPNET_CONFIG_EXPOSED',
              severity,
              url: base + path,
              description: `${name} file publicly accessible`,
              evidence: `File accessible at ${path}`,
              remediation: 'Block access to configuration files',
            });
          }
        }
      } catch {}
    }

    // Check Swagger exposure
    const swaggerPaths = ['/swagger', '/swagger/index.html', '/swagger/v1/swagger.json'];
    for (const path of swaggerPaths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok && (await resp.text()).includes('swagger')) {
          vulns.push({
            type: 'ASPNET_SWAGGER',
            severity: 'medium',
            url: base + path,
            description: 'Swagger API documentation exposed',
            evidence: 'Swagger UI accessible without auth',
            remediation: 'Disable Swagger in production or add authentication',
          });
          break;
        }
      } catch {}
    }

    return vulns;
  }

  // ============================================
  // SPRING BOOT SCANNER
  // ============================================

  async function scanSpring() {
    console.log('[Framework Scanner] Scanning Spring Boot...');
    const vulns = [];
    const base = location.origin;

    // Actuator endpoints (most dangerous first)
    const actuatorEndpoints = [
      { path: '/actuator/env', name: 'Environment', severity: 'critical', desc: 'Exposes all env vars including secrets' },
      { path: '/actuator/heapdump', name: 'Heap Dump', severity: 'critical', desc: 'JVM heap dump with secrets' },
      { path: '/actuator/jolokia', name: 'Jolokia JMX', severity: 'critical', desc: 'JMX over HTTP - RCE possible' },
      { path: '/actuator/shutdown', name: 'Shutdown', severity: 'critical', desc: 'Can shutdown application' },
      { path: '/actuator/loggers', name: 'Loggers', severity: 'high', desc: 'Can modify log levels' },
      { path: '/actuator/mappings', name: 'Mappings', severity: 'medium', desc: 'Exposes URL mappings' },
      { path: '/actuator/health', name: 'Health', severity: 'low', desc: 'Health status' },
      // Legacy paths
      { path: '/env', name: 'Env (Legacy)', severity: 'critical', desc: 'Legacy env endpoint' },
      { path: '/heapdump', name: 'Heapdump (Legacy)', severity: 'critical', desc: 'Legacy heapdump' },
    ];

    for (const { path, name, severity, desc } of actuatorEndpoints) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok) {
          const text = await resp.text();
          if (path.includes('heapdump') || text.includes('{') || text.includes('status')) {
            vulns.push({
              type: 'SPRING_ACTUATOR',
              severity,
              url: base + path,
              description: `Spring Actuator ${name} endpoint exposed: ${desc}`,
              evidence: `Endpoint accessible at ${path}`,
              remediation: 'Secure actuator endpoints with authentication or disable in production',
            });
          }
        }
      } catch {}
    }

    // H2 Console (Critical RCE)
    const h2Paths = ['/h2-console', '/h2-console/', '/console'];
    for (const path of h2Paths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok && (await resp.text()).toLowerCase().includes('h2 console')) {
          vulns.push({
            type: 'SPRING_H2_CONSOLE',
            severity: 'critical',
            url: base + path,
            description: 'H2 Database Console exposed - allows arbitrary SQL execution and RCE',
            evidence: 'H2 Console login page accessible',
            remediation: 'Disable H2 Console in production (spring.h2.console.enabled=false)',
          });
          break;
        }
      } catch {}
    }

    // Jolokia JMX (separate check)
    const jolokiaPaths = ['/jolokia', '/jolokia/list'];
    for (const path of jolokiaPaths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok && (await resp.text()).includes('MBeanServer')) {
          vulns.push({
            type: 'SPRING_JOLOKIA',
            severity: 'critical',
            url: base + path,
            description: 'Jolokia JMX endpoint exposed - allows JMX operations over HTTP, potential RCE',
            evidence: 'Jolokia MBean access available',
            remediation: 'Disable Jolokia or secure with authentication',
          });
          break;
        }
      } catch {}
    }

    // Swagger
    const swaggerPaths = ['/swagger-ui.html', '/swagger-ui/', '/v2/api-docs', '/v3/api-docs'];
    for (const path of swaggerPaths) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok) {
          const text = await resp.text();
          if (text.includes('swagger') || text.includes('openapi')) {
            vulns.push({
              type: 'SPRING_SWAGGER',
              severity: 'medium',
              url: base + path,
              description: 'Swagger/OpenAPI documentation exposed',
              evidence: 'API documentation accessible without auth',
              remediation: 'Secure Swagger UI with authentication or disable in production',
            });
            break;
          }
        }
      } catch {}
    }

    return vulns;
  }

  // ============================================
  // NEXT.JS SCANNER
  // ============================================

  async function scanNextJS(version) {
    console.log('[Framework Scanner] Scanning Next.js...');
    const vulns = [];
    const base = location.origin;

    // CVE-2025-29927 / CVE-2024-39693: Middleware bypass via x-middleware-subrequest
    const protectedPaths = ['/admin', '/dashboard', '/api/admin', '/api/private', '/settings', '/account'];

    for (const path of protectedPaths) {
      try {
        // First check if protected (401/403)
        const normalResp = await fetch(base + path, { credentials: 'include' });

        if (normalResp.status === 401 || normalResp.status === 403) {
          // Try bypass
          const bypassResp = await fetch(base + path, {
            credentials: 'include',
            headers: { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' },
          });

          if (bypassResp.ok || (bypassResp.status !== 401 && bypassResp.status !== 403)) {
            vulns.push({
              type: 'NEXTJS_MIDDLEWARE_BYPASS',
              severity: 'critical',
              url: base + path,
              cve: 'CVE-2025-29927',
              description: `Next.js middleware bypass - auth can be bypassed via x-middleware-subrequest header`,
              evidence: `Path ${path}: ${normalResp.status} → ${bypassResp.status} with bypass header`,
              remediation: 'Upgrade Next.js to 14.2.25+ or 15.2.3+',
            });
          }
        }
      } catch {}
    }

    // Check _next/data exposure
    try {
      const mainResp = await fetch(location.href, { credentials: 'include' });
      const html = await mainResp.text();
      const buildIdMatch = html.match(/buildId["']?\s*:\s*["']([^"']+)["']/);

      if (buildIdMatch) {
        const buildId = buildIdMatch[1];
        const dataPages = ['/index', '/admin', '/dashboard', '/user', '/settings'];

        for (const page of dataPages) {
          try {
            const dataUrl = `${base}/_next/data/${buildId}${page}.json`;
            const resp = await fetch(dataUrl, { credentials: 'include' });

            if (resp.ok) {
              const text = await resp.text();
              const sensitivePatterns = ['email', 'password', 'token', 'secret', 'apiKey'];

              if (sensitivePatterns.some(p => text.toLowerCase().includes(p))) {
                vulns.push({
                  type: 'NEXTJS_DATA_EXPOSURE',
                  severity: 'high',
                  url: dataUrl,
                  description: `Next.js _next/data exposes sensitive information for ${page}`,
                  evidence: 'Sensitive fields found in getServerSideProps/getStaticProps data',
                  remediation: 'Filter sensitive fields before returning props',
                });
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    // Check image optimization SSRF
    const ssrfPayloads = [
      'http://169.254.169.254/latest/meta-data/',
      'http://metadata.google.internal/',
      'http://127.0.0.1:22',
    ];

    for (const payload of ssrfPayloads) {
      try {
        const imgUrl = `${base}/_next/image?url=${encodeURIComponent(payload)}&w=64&q=75`;
        const resp = await fetch(imgUrl, { credentials: 'include' });

        if (resp.ok) {
          const text = await resp.text();
          if (text.includes('ami-') || text.includes('instance-id') || text.includes('SSH-')) {
            vulns.push({
              type: 'NEXTJS_IMAGE_SSRF',
              severity: 'critical',
              url: imgUrl,
              cve: 'CVE-2024-47831',
              description: 'Next.js image optimization SSRF - internal resources accessible',
              evidence: `SSRF via ${payload}`,
              remediation: 'Configure images.remotePatterns in next.config.js',
            });
            break;
          }
        }
      } catch {}
    }

    // Check source maps
    try {
      const mainResp = await fetch(location.href, { credentials: 'include' });
      const html = await mainResp.text();
      const jsFiles = html.match(/\/_next\/static\/[^"']+\.js/g) || [];

      for (const jsFile of jsFiles.slice(0, 3)) {
        try {
          const mapUrl = base + jsFile + '.map';
          const resp = await fetch(mapUrl, { credentials: 'include' });

          if (resp.ok && (await resp.text()).includes('mappings')) {
            vulns.push({
              type: 'NEXTJS_SOURCEMAPS',
              severity: 'medium',
              url: mapUrl,
              description: 'JavaScript source maps exposed - reveals original source code',
              evidence: 'Source map file accessible',
              remediation: 'Set productionBrowserSourceMaps: false in next.config.js',
            });
            break;
          }
        } catch {}
      }
    } catch {}

    // Check config exposure
    const configFiles = [
      { path: '/next.config.js', name: 'Next.js config' },
      { path: '/.env', name: 'Environment variables' },
      { path: '/.env.local', name: 'Local env' },
    ];

    for (const { path, name } of configFiles) {
      try {
        const resp = await fetch(base + path, { credentials: 'include' });
        if (resp.ok) {
          const text = await resp.text();
          if (text.includes('module.exports') || text.includes('DATABASE_URL') || text.includes('API_KEY')) {
            vulns.push({
              type: 'NEXTJS_CONFIG_EXPOSED',
              severity: path.includes('.env') ? 'critical' : 'medium',
              url: base + path,
              description: `${name} file publicly accessible`,
              evidence: `Config file at ${path}`,
              remediation: 'Block access to config files',
            });
          }
        }
      } catch {}
    }

    // Version-based CVE check
    if (version) {
      const parts = version.split('.').map(Number);
      const [major, minor, patch = 0] = parts;

      for (const cve of NEXTJS_CVES) {
        let affected = false;

        if (cve.cve === 'CVE-2025-29927') {
          affected = (major === 14 && (minor < 2 || (minor === 2 && patch < 25))) ||
                     (major === 15 && (minor < 2 || (minor === 2 && patch < 3)));
        } else if (cve.cve === 'CVE-2024-39693') {
          affected = major < 14 || (major === 14 && (minor < 2 || (minor === 2 && patch < 4)));
        } else if (cve.cve === 'CVE-2024-47831') {
          affected = major < 14 || (major === 14 && (minor < 2 || (minor === 2 && patch < 7)));
        }

        if (affected) {
          vulns.push({
            type: 'NEXTJS_CVE',
            severity: cve.severity,
            url: location.href,
            cve: cve.cve,
            description: `${cve.cve}: ${cve.desc} (affects ${cve.versions})`,
            evidence: `Detected version: ${version}`,
            remediation: `Upgrade Next.js to latest patched version`,
          });
        }
      }
    }

    return vulns;
  }

  // ============================================
  // MAIN SCAN FUNCTION
  // ============================================

  async function scan() {
    console.log('[Framework Scanner] Starting comprehensive framework scan...');

    const detected = await detectFrameworks();
    const results = [];

    if (detected.aspnet) {
      console.log(`[Framework Scanner] ASP.NET detected (${detected.aspnetVersion || 'version unknown'})`);
      reportFinding({
        type: 'FRAMEWORK_DETECTED',
        severity: 'info',
        url: location.href,
        description: `ASP.NET application detected (${detected.aspnetVersion || 'version unknown'})`,
      });
      const aspnetVulns = await scanASPNET();
      results.push(...aspnetVulns);
    }

    if (detected.spring) {
      console.log('[Framework Scanner] Spring Boot detected');
      reportFinding({
        type: 'FRAMEWORK_DETECTED',
        severity: 'info',
        url: location.href,
        description: 'Spring Boot application detected',
      });
      const springVulns = await scanSpring();
      results.push(...springVulns);
    }

    if (detected.nextjs) {
      console.log(`[Framework Scanner] Next.js detected (${detected.nextjsVersion || 'version unknown'})`);
      reportFinding({
        type: 'FRAMEWORK_DETECTED',
        severity: 'info',
        url: location.href,
        description: `Next.js application detected (${detected.nextjsVersion || 'version unknown'})`,
      });
      const nextjsVulns = await scanNextJS(detected.nextjsVersion);
      results.push(...nextjsVulns);
    }

    if (!detected.aspnet && !detected.spring && !detected.nextjs) {
      console.log('[Framework Scanner] No supported framework detected');
    }

    // Report all findings
    for (const vuln of results) {
      reportFinding(vuln);
    }

    console.log(`[Framework Scanner] Scan complete. Found ${results.length} vulnerabilities.`);

    const report = {
      findings: results,
      detected,
      findingCount: results.length,
      criticalCount: results.filter(f => f.severity === 'critical').length,
      highCount: results.filter(f => f.severity === 'high').length,
      url: location.href,
    };

    window.postMessage({
      type: '__lonkero_framework_scan_complete__',
      _n: _wn,
      ...report,
    }, '*');

    return report;
  }

  async function quickScan() {
    console.log('[Framework Scanner] Quick detection...');
    return await detectFrameworks();
  }

  function reportFinding(finding) {
    if (!_fwReady || !_wc) return;
    window.postMessage({
      type: '__lonkero_framework_finding__',
      _n: _wn,
      finding,
    }, '*');
    findings.push(finding);

    const severity = finding.severity?.toUpperCase() || 'INFO';
    console.log(`[Framework Scanner] ${severity}: ${finding.type}`, finding);
  }

  // ============================================
  // PUBLIC API
  // ============================================

  window.frameworkScanner = {
    scan,
    quickScan,
    detectFrameworks,
    scanASPNET,
    scanSpring,
    scanNextJS,
    getFindings: () => findings,
    clearFindings: () => { findings.length = 0; },
  };

  // Listen for scan requests
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data?.type === '__lonkero_run_framework_scan__') {
      scan();
    }
  });

  console.log('[Lonkero] Framework Scanner v1.0 loaded. Use frameworkScanner.scan() to scan.');
})();
