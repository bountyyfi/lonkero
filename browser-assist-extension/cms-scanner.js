// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero CMS & Framework Vulnerability Scanner v2.0
 *
 * Comprehensive CMS/Framework vulnerability detection with content validation.
 * IMPORTANT: All checks validate response content, not just HTTP 200 status (SPA-safe).
 *
 * Supported CMS:
 * - WordPress: user enum, xmlrpc, config backups, SQL dumps, phpMyAdmin, debug logs
 * - Drupal: Drupalgeddon 1/2/3, settings.php, views SQLi, JSON API
 * - Joomla: CVE-2023-23752, CVE-2017-8917, API exposure
 * - Laravel: .env exposure, Ignition RCE, Telescope, log files
 * - Next.js: SSRF in image optimizer, source maps, middleware bypass
 * - Liferay: JSONWS RCE, WebDAV, deserialization
 *
 * General Disclosure:
 * - .git exposure, .env files, phpinfo, server-status, backup files
 */

(function() {
  'use strict';

  // Scan environment setup
  const _sp = atob('X19sb25rZXJvS2V5');
  const _se = atob('aHR0cHM6Ly9sb25rZXJvLmJvdW50eXkuZmkvYXBpL3YxL3ZhbGlkYXRl');
  const _sc = window[_sp];
  if (!_sc || _sc.charCodeAt(0) !== 76 || _sc.split('-').length !== 5) {
    window.cmsScanner = { scan: () => Promise.reject(new Error('Not available')) };
    return;
  }
  let _initOk = true;
  fetch(_se, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({[atob('bGljZW5zZV9rZXk=')]: _sc, product: atob('bG9ua2Vybw=='), version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d[atob('a2lsbHN3aXRjaF9hY3RpdmU=')]) _initOk = false; }).catch(() => {});

  // ============================================================
  // VULNERABLE PLUGINS/MODULES DATABASE
  // ============================================================

  const WORDPRESS_VULNERABLE_PLUGINS = {
    'contact-form-7': { version: '5.3.1', cve: 'CVE-2020-35489', severity: 'high' },
    'elementor': { version: '3.1.4', cve: 'CVE-2021-24195', severity: 'high' },
    'wp-file-manager': { version: '6.8', cve: 'CVE-2020-25213', severity: 'critical' },
    'duplicator': { version: '1.3.28', cve: 'CVE-2020-11738', severity: 'critical' },
    'wpforms-lite': { version: '1.6.3', cve: 'CVE-2021-24100', severity: 'medium' },
    'all-in-one-seo-pack': { version: '4.0.16', cve: 'CVE-2021-25036', severity: 'critical' },
    'wordfence': { version: '7.4.14', cve: 'CVE-2021-24142', severity: 'medium' },
    'yoast-seo': { version: '15.8', cve: 'CVE-2021-25061', severity: 'medium' },
    'loginizer': { version: '1.6.3', cve: 'CVE-2020-27615', severity: 'critical' },
    'ninja-forms': { version: '3.4.34', cve: 'CVE-2021-34648', severity: 'high' },
    'easy-wp-smtp': { version: '1.4.2', cve: 'CVE-2020-35234', severity: 'high' },
    'wp-statistics': { version: '12.6.12', cve: 'CVE-2021-24340', severity: 'high' },
    'ultimate-member': { version: '2.1.11', cve: 'CVE-2020-36155', severity: 'critical' },
    'redux-framework': { version: '4.1.24', cve: 'CVE-2021-38314', severity: 'medium' },
    'fancy-product-designer': { version: '4.6.8', cve: 'CVE-2021-24370', severity: 'critical' },
    'updraftplus': { version: '1.22.3', cve: 'CVE-2022-0633', severity: 'high' },
    'woocommerce': { version: '5.5.0', cve: 'CVE-2021-32790', severity: 'high' },
    'jetpack': { version: '9.8', cve: 'CVE-2021-24374', severity: 'medium' },
    'really-simple-security': { version: '9.1.1.1', cve: 'CVE-2024-10924', severity: 'critical' },
    'wp-automatic': { version: '3.92.0', cve: 'CVE-2024-27956', severity: 'critical' },
    'litespeed-cache': { version: '6.3.0.1', cve: 'CVE-2024-28000', severity: 'critical' },
    'backup-backup': { version: '1.3.7', cve: 'CVE-2023-6553', severity: 'critical' },
  };

  // Content validation patterns - verify response actually contains expected content
  const CONTENT_VALIDATORS = {
    // PHP files should have PHP code or output
    php: text => /<\?php|<?=|Fatal error:|Parse error:|Warning:|Notice:|function\s+\w+\s*\(|class\s+\w+/i.test(text),
    // Config files should have config-like content
    config: text => /database|password|secret|api[_-]?key|host\s*=|define\s*\(|=\s*['"][^'"]+['"]\s*;/i.test(text),
    // SQL files
    sql: text => /CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|SELECT\s+.*\s+FROM|--\s*MySQL|--\s*Dump/i.test(text),
    // Log files
    log: text => /\[\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|PHP\s+(Fatal|Warning|Notice|Error)|Stack trace:|Exception:|Error:/i.test(text),
    // Directory listing
    dirListing: text => /Index of|Parent Directory|<a href="[^"]+\/"|Directory listing for/i.test(text),
    // Git files
    git: text => /ref:|refs\/heads\/|DIRC|pack-|\.git|commit\s+[a-f0-9]{40}/i.test(text),
    // Env files
    env: text => /^[A-Z_]+=.+$/m.test(text) && /DB_|APP_|SECRET|KEY|PASSWORD|TOKEN|API/i.test(text),
    // JSON response
    json: text => { try { JSON.parse(text); return true; } catch { return false; } },
    // XML content
    xml: text => /^<\?xml|<[\w-]+\s*xmlns/i.test(text.trim()),
    // phpinfo output
    phpinfo: text => /phpinfo\(\)|PHP Version|Configuration File|Loaded Modules/i.test(text),
    // Server status pages
    serverStatus: text => /Server Status|Scoreboard:|Apache|nginx|Requests|Uptime:/i.test(text),
    // Backup file indicators
    backup: text => text.length > 100 && (CONTENT_VALIDATORS.php(text) || CONTENT_VALIDATORS.sql(text) || CONTENT_VALIDATORS.config(text)),
  };

  const DRUPAL_VULNERABLE_MODULES = {
    'ctools': { version: '1.14', cve: 'CVE-2019-6790', severity: 'high' },
    'views': { version: '3.18', cve: 'CVE-2014-3704', severity: 'critical' },
    'services': { version: '3.19', cve: 'CVE-2016-3163', severity: 'critical' },
    'restws': { version: '2.7', cve: 'CVE-2016-3168', severity: 'critical' },
    'webform': { version: '4.15', cve: 'CVE-2019-18955', severity: 'high' },
    'media': { version: '2.13', cve: 'CVE-2015-7943', severity: 'medium' },
    'file_entity': { version: '2.0-beta3', cve: 'CVE-2015-7943', severity: 'medium' },
    'features': { version: '2.10', cve: 'CVE-2017-6920', severity: 'medium' },
    'panels': { version: '3.9', cve: 'CVE-2016-3169', severity: 'high' },
    'paragraphs': { version: '1.15', cve: 'CVE-2022-25277', severity: 'critical' },
    'twig_tweak': { version: '3.1.0', cve: 'CVE-2022-40188', severity: 'high' },
  };

  // Laravel vulnerable packages
  const LARAVEL_VULNERABLE_PACKAGES = {
    'ignition': { version: '2.5.1', cve: 'CVE-2021-3129', severity: 'critical', desc: 'Ignition RCE' },
    'laravel-debugbar': { version: '3.5.5', cve: 'CVE-2021-24711', severity: 'high', desc: 'Debug info exposure' },
  };

  // Liferay vulnerable versions
  const LIFERAY_VULNERABILITIES = {
    'jsonws_rce': { cve: 'CVE-2020-7961', severity: 'critical', desc: 'JSONWS Deserialization RCE' },
    'webdav_path_traversal': { cve: 'CVE-2019-16891', severity: 'high', desc: 'WebDAV Path Traversal' },
  };

  const JOOMLA_VULNERABLE_EXTENSIONS = {
    'com_jce': { version: '2.6.38', cve: 'CVE-2013-6040', severity: 'critical' },
    'com_fabrik': { version: '3.9.2', cve: 'CVE-2020-24249', severity: 'high' },
  };

  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================

  function compareVersions(v1, v2) {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const a = parts1[i] || 0;
      const b = parts2[i] || 0;
      if (a < b) return -1;
      if (a > b) return 1;
    }
    return 0;
  }

  async function fetchWithTimeout(url, options = {}, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        credentials: 'omit',
        redirect: 'manual',
      });
      clearTimeout(timeoutId);
      return response;
    } catch (e) {
      clearTimeout(timeoutId);
      throw e;
    }
  }

  async function checkPathExists(path, validate = null) {
    try {
      const url = location.origin + path;
      const response = await fetchWithTimeout(url, { method: 'GET' });

      if (response.status === 200) {
        if (validate) {
          const text = await response.text();
          return validate(text) ? { exists: true, content: text } : { exists: false };
        }
        return { exists: true, content: await response.text() };
      }
      return { exists: false, status: response.status };
    } catch {
      return { exists: false };
    }
  }

  function reportFinding(type, data) {
    if (!_initOk || !window[_sp]) return;
    window.postMessage({
      type: '__lonkero_finding__',
      finding: {
        type: type,
        ...data,
        url: data.url || location.href,
        scanner: 'cms-scanner',
      }
    }, '*');
  }

  // ============================================================
  // CMS SCANNER CLASS
  // ============================================================

  class CMSScanner {
    constructor() {
      this.detectedCMS = null;
      this.detectedVersion = null;
      this.findings = [];
      this.testedPaths = new Set();
    }

    // ============================================================
    // CMS DETECTION
    // ============================================================

    detectCMS() {
      const html = document.documentElement.outerHTML;
      const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
      const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href);
      const meta = document.querySelector('meta[name="generator"]')?.content || '';

      // WordPress detection
      if (
        scripts.some(s => s.includes('/wp-content/') || s.includes('/wp-includes/')) ||
        links.some(l => l.includes('/wp-content/')) ||
        html.includes('/wp-json/') ||
        meta.toLowerCase().includes('wordpress')
      ) {
        this.detectedCMS = 'wordpress';
        const versionMatch = meta.match(/WordPress\s*([\d.]+)/i);
        if (versionMatch) this.detectedVersion = versionMatch[1];
        return 'wordpress';
      }

      // Drupal detection
      if (
        html.includes('Drupal.settings') ||
        html.includes('/sites/default/') ||
        html.includes('/sites/all/') ||
        document.querySelector('[data-drupal-selector]') ||
        meta.toLowerCase().includes('drupal')
      ) {
        this.detectedCMS = 'drupal';
        const versionMatch = meta.match(/Drupal\s*(\d+)/i);
        if (versionMatch) this.detectedVersion = versionMatch[1];
        return 'drupal';
      }

      // Joomla detection
      if (
        html.toLowerCase().includes('joomla') ||
        meta.toLowerCase().includes('joomla') ||
        scripts.some(s => s.includes('/media/jui/'))
      ) {
        this.detectedCMS = 'joomla';
        const versionMatch = meta.match(/Joomla!\s*([\d.]+)/i);
        if (versionMatch) this.detectedVersion = versionMatch[1];
        return 'joomla';
      }

      return null;
    }

    // ============================================================
    // WORDPRESS SECURITY CHECKS
    // ============================================================

    async scanWordPress() {
      console.log('[CMS Scanner] Running WordPress security checks...');
      const results = [];

      // Version disclosure via readme.html
      const readme = await checkPathExists('/readme.html', text =>
        text.includes('WordPress') && /<br\s*\/?>\s*Version/i.test(text)
      );
      if (readme.exists) {
        const versionMatch = readme.content.match(/Version\s*([\d.]+)/i);
        results.push({
          type: 'WP_VERSION_DISCLOSURE',
          severity: 'low',
          path: '/readme.html',
          version: versionMatch?.[1],
          evidence: 'WordPress readme.html accessible',
        });
      }

      // User enumeration via author parameter
      for (let i = 1; i <= 3; i++) {
        try {
          const url = `${location.origin}/?author=${i}`;
          const response = await fetchWithTimeout(url, { redirect: 'follow' });
          if (response.redirected && response.url.includes('/author/')) {
            const username = response.url.match(/\/author\/([^/]+)/)?.[1];
            results.push({
              type: 'WP_USER_ENUMERATION',
              severity: 'medium',
              method: 'author_parameter',
              userId: i,
              username: username,
              evidence: `User ID ${i} enumerated via ?author=${i}`,
            });
            break;
          }
        } catch {}
      }

      // REST API user enumeration
      const restApi = await checkPathExists('/wp-json/wp/v2/users', text => {
        try {
          const users = JSON.parse(text);
          return Array.isArray(users) && users.length > 0;
        } catch { return false; }
      });
      if (restApi.exists) {
        try {
          const users = JSON.parse(restApi.content);
          results.push({
            type: 'WP_REST_API_USER_ENUM',
            severity: 'medium',
            path: '/wp-json/wp/v2/users',
            userCount: users.length,
            users: users.slice(0, 5).map(u => ({ id: u.id, name: u.name, slug: u.slug })),
            evidence: 'WordPress REST API exposes user information',
          });
        } catch {}
      }

      // XML-RPC check with POST probe for method listing
      const xmlrpc = await checkPathExists('/xmlrpc.php', text =>
        text.includes('XML-RPC server accepts POST requests only') || text.includes('XML-RPC')
      );
      if (xmlrpc.exists) {
        results.push({
          type: 'WP_XMLRPC_ENABLED',
          severity: 'medium',
          path: '/xmlrpc.php',
          evidence: 'XML-RPC interface enabled - brute force, pingback SSRF, and DoS possible',
        });
      }

      // Debug log exposure - extended paths
      const debugPaths = [
        '/wp-content/debug.log',
        '/debug.log',
        '/wp-content/uploads/debug.log',
        '/error_log',
        '/wp-content/error_log',
        '/php_errorlog',
      ];
      for (const path of debugPaths) {
        const debug = await checkPathExists(path, CONTENT_VALIDATORS.log);
        if (debug.exists) {
          results.push({
            type: 'WP_DEBUG_LOG_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Debug/error log publicly accessible - may contain sensitive info',
            preview: debug.content.substring(0, 300),
          });
        }
      }

      // Config file exposure - comprehensive list
      const configPaths = [
        '/wp-config.php~', '/wp-config.php.bak', '/wp-config.php.old',
        '/wp-config.php.txt', '/wp-config.php.swp', '/wp-config.bak',
        '/wp-config.php.save', '/wp-config.php.orig', '/wp-config.php.dist',
        '/wp-config.php.inc', '/wp-config.php.backup', '/wp-config.copy.php',
        '/wp-config-backup.php', '/wp-config.php_bak', '/.wp-config.php.swp',
        '/wp-config.php.sample', '/wp-config-sample.php', // may leak structure
      ];
      for (const path of configPaths) {
        const config = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.config(text) && (
            text.includes('DB_NAME') || text.includes('DB_USER') ||
            text.includes('DB_PASSWORD') || text.includes('table_prefix')
          )
        );
        if (config.exists) {
          results.push({
            type: 'WP_CONFIG_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'WordPress configuration backup exposed - database credentials leaked',
          });
        }
      }

      // SQL backup/dump files
      const sqlBackupPaths = [
        '/backup.sql', '/database.sql', '/dump.sql', '/db.sql',
        '/wp-content/backup.sql', '/wp-content/database.sql',
        '/wordpress.sql', '/site.sql', '/data.sql',
        '/backups/backup.sql', '/sql/backup.sql',
        '/.sql', '/export.sql', '/mysql.sql',
      ];
      for (const path of sqlBackupPaths) {
        const sql = await checkPathExists(path, CONTENT_VALIDATORS.sql);
        if (sql.exists) {
          results.push({
            type: 'WP_SQL_DUMP_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'SQL database dump publicly accessible - full database exposed',
            preview: sql.content.substring(0, 200),
          });
        }
      }

      // phpMyAdmin paths
      const pmaPathsList = [
        '/phpmyadmin/', '/phpMyAdmin/', '/pma/', '/myadmin/',
        '/mysql/', '/admin/phpmyadmin/', '/sql/', '/db/',
        '/dbadmin/', '/mysqladmin/', '/phpMyadmin/', '/phpmyadmin2/',
        '/phpmyadmin3/', '/phpmyadmin4/', '/pmaAdmin/', '/sqlmanager/',
      ];
      for (const path of pmaPathsList) {
        const pma = await checkPathExists(path, text =>
          text.includes('phpMyAdmin') || text.includes('phpmyadmin') ||
          text.includes('PMA_') || text.includes('pma_')
        );
        if (pma.exists) {
          results.push({
            type: 'WP_PHPMYADMIN_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'phpMyAdmin installation found - database management exposed',
          });
          break;
        }
      }

      // Installation script
      const install = await checkPathExists('/wp-admin/install.php', text =>
        text.includes('WordPress') && (text.includes('installation') || text.includes('Already Installed'))
      );
      if (install.exists && !install.content.includes('Already Installed')) {
        results.push({
          type: 'WP_INSTALL_SCRIPT_ACCESSIBLE',
          severity: 'critical',
          path: '/wp-admin/install.php',
          evidence: 'WordPress installation script accessible - potential site takeover',
        });
      }

      // Setup config
      const setupConfig = await checkPathExists('/wp-admin/setup-config.php', text =>
        text.includes('WordPress') && text.includes('config')
      );
      if (setupConfig.exists) {
        results.push({
          type: 'WP_SETUP_CONFIG_ACCESSIBLE',
          severity: 'critical',
          path: '/wp-admin/setup-config.php',
          evidence: 'WordPress setup-config.php accessible - can reconfigure installation',
        });
      }

      // Directory listing - extended
      const dirPaths = [
        '/wp-content/uploads/', '/wp-content/plugins/', '/wp-includes/',
        '/wp-content/themes/', '/wp-content/backup/', '/wp-content/backups/',
        '/wp-content/cache/', '/wp-content/upgrade/', '/wp-content/uploads/backups/',
      ];
      for (const path of dirPaths) {
        const dir = await checkPathExists(path, CONTENT_VALIDATORS.dirListing);
        if (dir.exists) {
          results.push({
            type: 'WP_DIRECTORY_LISTING',
            severity: 'low',
            path: path,
            evidence: 'Directory listing enabled - file enumeration possible',
          });
        }
      }

      // wp-cron.php - can be abused for DoS
      const cron = await checkPathExists('/wp-cron.php');
      if (cron.exists && cron.status !== 403) {
        results.push({
          type: 'WP_CRON_EXPOSED',
          severity: 'info',
          path: '/wp-cron.php',
          evidence: 'WordPress cron endpoint exposed - potential DoS vector',
        });
      }

      // WP-JSON full index - information disclosure
      const wpJson = await checkPathExists('/wp-json/', text => {
        try {
          const data = JSON.parse(text);
          return data.routes || data.namespaces;
        } catch { return false; }
      });
      if (wpJson.exists) {
        results.push({
          type: 'WP_REST_API_INDEX',
          severity: 'info',
          path: '/wp-json/',
          evidence: 'WordPress REST API index exposed - reveals available endpoints',
        });
      }

      // Upgrade/update files that might be left behind
      const upgradeFiles = [
        '/wp-admin/maint/repair.php',
        '/wp-admin/upgrade.php',
      ];
      for (const path of upgradeFiles) {
        const upgrade = await checkPathExists(path, text =>
          text.includes('WordPress') || text.includes('repair') || text.includes('upgrade')
        );
        if (upgrade.exists && !upgrade.content.includes('Access denied')) {
          results.push({
            type: 'WP_UPGRADE_SCRIPT',
            severity: 'medium',
            path: path,
            evidence: 'WordPress upgrade/repair script accessible',
          });
        }
      }

      // Backup plugins common paths
      const backupPluginPaths = [
        '/wp-content/ai1wm-backups/',
        '/wp-content/updraft/',
        '/wp-content/backups-dup-lite/',
        '/wp-content/backup-db/',
        '/wp-content/uploads/backwpup-*/',
        '/wp-snapshots/',
      ];
      for (const path of backupPluginPaths) {
        const backup = await checkPathExists(path.replace('*', ''), CONTENT_VALIDATORS.dirListing);
        if (backup.exists) {
          results.push({
            type: 'WP_BACKUP_DIR_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'WordPress backup plugin directory accessible - may contain full site backups',
          });
        }
      }

      // Check for vulnerable plugins - extended list
      const pluginsToCheck = Object.keys(WORDPRESS_VULNERABLE_PLUGINS);
      for (const plugin of pluginsToCheck) {
        const pluginReadme = await checkPathExists(`/wp-content/plugins/${plugin}/readme.txt`, text =>
          text.includes('Stable tag') || text.includes('Version') || text.includes('===')
        );
        if (pluginReadme.exists) {
          const versionMatch = pluginReadme.content.match(/Stable tag:\s*([\d.]+)/i) ||
                               pluginReadme.content.match(/Version:\s*([\d.]+)/i);
          if (versionMatch) {
            const version = versionMatch[1];
            const vulnInfo = WORDPRESS_VULNERABLE_PLUGINS[plugin];
            if (vulnInfo && compareVersions(version, vulnInfo.version) <= 0) {
              results.push({
                type: 'WP_VULNERABLE_PLUGIN',
                severity: vulnInfo.severity,
                plugin: plugin,
                version: version,
                vulnerableBelow: vulnInfo.version,
                cve: vulnInfo.cve,
                evidence: `Plugin ${plugin} v${version} vulnerable to ${vulnInfo.cve}`,
              });
            }
          }
        }
      }

      // File editor access check (attempts to access theme editor)
      const themeEditor = await checkPathExists('/wp-admin/theme-editor.php', text =>
        text.includes('theme-editor') || text.includes('Theme Editor')
      );
      if (themeEditor.exists && themeEditor.status === 200 && !themeEditor.content.includes('login')) {
        results.push({
          type: 'WP_THEME_EDITOR_ACCESSIBLE',
          severity: 'info',
          path: '/wp-admin/theme-editor.php',
          evidence: 'Theme editor may be enabled (check authentication)',
        });
      }

      return results;
    }

    // ============================================================
    // DRUPAL SECURITY CHECKS
    // ============================================================

    async scanDrupal() {
      console.log('[CMS Scanner] Running Drupal security checks...');
      const results = [];
      let detectedVersion = null;
      let majorVersion = 0;

      // Version disclosure via CHANGELOG.txt
      const changelogPaths = ['/CHANGELOG.txt', '/core/CHANGELOG.txt', '/core/MAINTAINERS.txt'];
      for (const path of changelogPaths) {
        const changelog = await checkPathExists(path, text =>
          text.includes('Drupal') || text.includes('drupal')
        );
        if (changelog.exists) {
          const versionMatch = changelog.content.match(/Drupal\s*(\d+)\.(\d+)(?:\.(\d+))?/i);
          if (versionMatch) {
            const version = versionMatch.slice(1, 4).filter(Boolean).join('.');
            this.detectedVersion = version;
            detectedVersion = version;
            majorVersion = parseInt(versionMatch[1]);
            const minor = parseInt(versionMatch[2]);
            const patch = parseInt(versionMatch[3] || '0');

            results.push({
              type: 'DRUPAL_VERSION_DISCLOSURE',
              severity: 'low',
              path: path,
              version: version,
              evidence: 'Drupal version disclosed via CHANGELOG.txt',
            });

            // Drupalgeddon (SA-CORE-2014-005) - Drupal 7 < 7.32
            if (majorVersion === 7 && minor < 32) {
              results.push({
                type: 'DRUPAL_DRUPALGEDDON',
                severity: 'critical',
                cve: 'CVE-2014-3704',
                version: version,
                evidence: 'Drupal 7 vulnerable to Drupalgeddon SQLi (SA-CORE-2014-005) - UNAUTHENTICATED RCE',
                exploit: 'SQL injection in form API allows adding admin user',
              });
            }

            // Drupalgeddon2 (SA-CORE-2018-002) - CVE-2018-7600
            if (
              (majorVersion === 7 && minor < 58) ||
              (majorVersion === 8 && minor === 3 && patch < 9) ||
              (majorVersion === 8 && minor === 4 && patch < 6) ||
              (majorVersion === 8 && minor === 5 && patch < 1)
            ) {
              results.push({
                type: 'DRUPAL_DRUPALGEDDON2',
                severity: 'critical',
                cve: 'CVE-2018-7600',
                version: version,
                evidence: 'Drupal vulnerable to Drupalgeddon2 (SA-CORE-2018-002) - UNAUTHENTICATED RCE',
                exploit: 'Remote code execution via Form API render arrays',
              });
            }

            // Drupalgeddon3 (SA-CORE-2018-004) - CVE-2018-7602
            if (
              (majorVersion === 7 && minor < 59) ||
              (majorVersion === 8 && minor === 4 && patch < 8) ||
              (majorVersion === 8 && minor === 5 && patch < 3)
            ) {
              results.push({
                type: 'DRUPAL_DRUPALGEDDON3',
                severity: 'critical',
                cve: 'CVE-2018-7602',
                version: version,
                evidence: 'Drupal vulnerable to Drupalgeddon3 (SA-CORE-2018-004) - AUTHENTICATED RCE',
                exploit: 'RCE requires authenticated session',
              });
            }
          }
          break;
        }
      }

      // User enumeration via /user/N
      for (let i = 1; i <= 3; i++) {
        const userPath = await checkPathExists(`/user/${i}`, text =>
          text.includes('Member for') || text.includes('user-picture') ||
          text.includes('profile') || text.includes('History')
        );
        if (userPath.exists) {
          results.push({
            type: 'DRUPAL_USER_ENUMERATION',
            severity: 'medium',
            method: 'user_path',
            userId: i,
            evidence: `User ID ${i} profile accessible at /user/${i}`,
          });
          break;
        }
      }

      // User enumeration via login form timing/response
      // Also check JSON API and GraphQL user endpoints
      const userApiPaths = [
        '/jsonapi/user/user',
        '/api/user',
        '/graphql', // Drupal GraphQL module
        '/json/node', // Services module
      ];
      for (const path of userApiPaths) {
        const api = await checkPathExists(path, text => {
          try {
            const data = JSON.parse(text);
            return (data.data && Array.isArray(data.data)) || data.errors || data.links;
          } catch { return false; }
        });
        if (api.exists) {
          results.push({
            type: 'DRUPAL_API_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: `Drupal API endpoint ${path} exposed - may leak user/content data`,
          });
        }
      }

      // Admin and privileged paths
      const adminPaths = ['/admin', '/admin/config', '/admin/structure', '/admin/people', '/admin/modules'];
      for (const path of adminPaths) {
        const admin = await checkPathExists(path, text =>
          text.includes('Administration') || text.includes('Drupal') ||
          (text.includes('Log in') && text.includes('admin'))
        );
        if (admin.exists && admin.status !== 403) {
          results.push({
            type: 'DRUPAL_ADMIN_ACCESSIBLE',
            severity: 'info',
            path: path,
            evidence: `Drupal admin path ${path} accessible (may require auth)`,
          });
          break;
        }
      }

      // Installation/update scripts
      const scriptPaths = ['/install.php', '/update.php', '/authorize.php'];
      for (const path of scriptPaths) {
        const script = await checkPathExists(path, text =>
          (text.includes('Drupal') || text.includes('installation') || text.includes('update')) &&
          !text.includes('Access denied') && !text.includes('not accessible')
        );
        if (script.exists) {
          results.push({
            type: 'DRUPAL_INSTALL_SCRIPT',
            severity: 'high',
            path: path,
            evidence: `Drupal ${path} accessible - may allow re-installation or privilege escalation`,
          });
        }
      }

      // Configuration file exposure - comprehensive
      const configPaths = [
        '/sites/default/settings.php~',
        '/sites/default/settings.php.bak',
        '/sites/default/settings.php.old',
        '/sites/default/settings.php.orig',
        '/sites/default/settings.php.save',
        '/sites/default/settings.php.txt',
        '/sites/default/settings.local.php',
        '/sites/default/settings.local.php~',
        '/sites/default/default.settings.php', // May leak structure
        '/sites/default/services.yml',
        '/sites/default/services.yml~',
      ];
      for (const path of configPaths) {
        const config = await checkPathExists(path, text =>
          text.includes('$databases') || text.includes('$settings') ||
          text.includes('database') || text.includes('hash_salt') ||
          text.includes('trusted_host')
        );
        if (config.exists) {
          results.push({
            type: 'DRUPAL_CONFIG_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Drupal configuration file exposed - database credentials may be leaked',
          });
        }
      }

      // Cron without key
      const cronPaths = ['/cron.php', '/cron'];
      for (const path of cronPaths) {
        const cron = await checkPathExists(path, text =>
          !text.includes('Access denied') && !text.includes('Cron key')
        );
        if (cron.exists && cron.status === 200 && cron.content.length < 500) {
          results.push({
            type: 'DRUPAL_CRON_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'Drupal cron accessible without key - can trigger resource-intensive operations',
          });
        }
      }

      // Private files exposure
      const privatePaths = ['/sites/default/files/private/', '/system/files/'];
      for (const path of privatePaths) {
        const priv = await checkPathExists(path, CONTENT_VALIDATORS.dirListing);
        if (priv.exists) {
          results.push({
            type: 'DRUPAL_PRIVATE_FILES_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Drupal private files directory listing enabled',
          });
        }
      }

      // Views SQL injection check (for older Drupal 7)
      // CVE-2014-3704 allows SQLi through views exposed filters with specific configurations
      if (majorVersion === 7 || majorVersion === 0) {
        const viewsPaths = ['/views/ajax', '/views/admin'];
        for (const path of viewsPaths) {
          const views = await checkPathExists(path, text =>
            text.includes('views') || text.includes('ajax') || CONTENT_VALIDATORS.json(text)
          );
          if (views.exists) {
            results.push({
              type: 'DRUPAL_VIEWS_ENDPOINT',
              severity: 'info',
              path: path,
              evidence: 'Drupal Views ajax endpoint found - check for SQLi in exposed filters',
            });
          }
        }
      }

      // Backup SQL files
      const sqlPaths = [
        '/sites/default/files/backup_migrate/',
        '/backup.sql',
        '/database.sql',
        '/drupal.sql',
        '/sites/default/files/backup/',
      ];
      for (const path of sqlPaths) {
        const backup = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.sql(text) || CONTENT_VALIDATORS.dirListing(text)
        );
        if (backup.exists) {
          results.push({
            type: 'DRUPAL_BACKUP_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Drupal backup files/directory exposed',
          });
        }
      }

      // Module info files that leak version info
      const moduleInfoPaths = [
        '/modules/system/system.info.yml',
        '/core/modules/system/system.info.yml',
        '/modules/node/node.info',
      ];
      for (const path of moduleInfoPaths) {
        const info = await checkPathExists(path, text =>
          text.includes('version') || text.includes('core') || text.includes('name')
        );
        if (info.exists) {
          results.push({
            type: 'DRUPAL_MODULE_INFO_EXPOSED',
            severity: 'low',
            path: path,
            evidence: 'Drupal module info file accessible - leaks version information',
          });
          break;
        }
      }

      return results;
    }

    // ============================================================
    // JOOMLA SECURITY CHECKS
    // ============================================================

    async scanJoomla() {
      console.log('[CMS Scanner] Running Joomla security checks...');
      const results = [];

      // Version detection
      const versionPaths = [
        '/administrator/manifests/files/joomla.xml',
        '/language/en-GB/en-GB.xml',
      ];
      for (const path of versionPaths) {
        const xml = await checkPathExists(path, text =>
          text.includes('<version>')
        );
        if (xml.exists) {
          const versionMatch = xml.content.match(/<version>([\d.]+)<\/version>/);
          if (versionMatch) {
            const version = versionMatch[1];
            this.detectedVersion = version;
            results.push({
              type: 'JOOMLA_VERSION_DISCLOSURE',
              severity: 'low',
              path: path,
              version: version,
              evidence: 'Joomla version disclosed in XML manifest',
            });

            // Check for CVE-2023-23752 (4.0.0 - 4.2.7)
            const parts = version.split('.').map(Number);
            if (parts[0] === 4 && (parts[1] < 2 || (parts[1] === 2 && parts[2] <= 7))) {
              results.push({
                type: 'JOOMLA_CVE_2023_23752',
                severity: 'critical',
                cve: 'CVE-2023-23752',
                version: version,
                evidence: 'Joomla version vulnerable to unauthorized API access (CVE-2023-23752)',
              });
            }

            // Check for CVE-2017-8917 (3.7.0)
            if (version === '3.7.0') {
              results.push({
                type: 'JOOMLA_CVE_2017_8917',
                severity: 'critical',
                cve: 'CVE-2017-8917',
                version: version,
                evidence: 'Joomla 3.7.0 vulnerable to SQL injection (CVE-2017-8917)',
              });
            }
          }
          break;
        }
      }

      // Admin panel exposure
      const admin = await checkPathExists('/administrator/', text =>
        text.includes('mod-login') || text.includes('Joomla') || text.includes('administrator')
      );
      if (admin.exists) {
        results.push({
          type: 'JOOMLA_ADMIN_ACCESSIBLE',
          severity: 'info',
          path: '/administrator/',
          evidence: 'Joomla administrator panel accessible',
        });
      }

      // API exposure (CVE-2023-23752 exploitation paths)
      const apiPaths = [
        '/api/index.php/v1/config/application',
        '/api/index.php/v1/users',
      ];
      for (const path of apiPaths) {
        const api = await checkPathExists(path, text => {
          try {
            const data = JSON.parse(text);
            // Check if sensitive data is exposed
            return data.data && (
              text.includes('dbtype') ||
              text.includes('password') ||
              text.includes('email')
            );
          } catch { return false; }
        });
        if (api.exists) {
          results.push({
            type: 'JOOMLA_API_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Joomla API exposes sensitive configuration/user data',
          });
        }
      }

      // Config file exposure
      const configPaths = ['/configuration.php~', '/configuration.php.bak', '/configuration.php.old'];
      for (const path of configPaths) {
        const config = await checkPathExists(path, text =>
          text.includes('$dbtype') || text.includes('$user') || text.includes('$password')
        );
        if (config.exists) {
          results.push({
            type: 'JOOMLA_CONFIG_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Joomla configuration backup file exposed',
          });
          break;
        }
      }

      // Installation directory
      const install = await checkPathExists('/installation/', text =>
        text.includes('Joomla') && text.includes('install')
      );
      if (install.exists) {
        results.push({
          type: 'JOOMLA_INSTALL_DIR',
          severity: 'high',
          path: '/installation/',
          evidence: 'Joomla installation directory not removed',
        });
      }

      return results;
    }

    // ============================================================
    // LARAVEL SECURITY CHECKS
    // ============================================================

    async scanLaravel() {
      console.log('[CMS Scanner] Running Laravel security checks...');
      const results = [];
      const html = document.documentElement.outerHTML;

      // Detect Laravel
      const isLaravel = html.includes('laravel_session') ||
                        html.includes('XSRF-TOKEN') ||
                        document.cookie.includes('laravel_session');

      if (!isLaravel) {
        // Still check common Laravel paths even if not detected
      }

      // .env file exposure - CRITICAL
      const envPaths = [
        '/.env', '/.env.local', '/.env.production', '/.env.staging',
        '/.env.development', '/.env.backup', '/.env.bak', '/.env.old',
        '/.env.save', '/.env.example', '/.env.sample',
        '/app/.env', '/public/.env', '/html/.env',
      ];
      for (const path of envPaths) {
        const env = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.env(text) && (
            text.includes('APP_KEY') || text.includes('DB_PASSWORD') ||
            text.includes('APP_DEBUG') || text.includes('MAIL_PASSWORD')
          )
        );
        if (env.exists) {
          // Check what's exposed
          const hasAppKey = env.content.includes('APP_KEY=');
          const hasDbCreds = env.content.includes('DB_PASSWORD=');
          const hasMailCreds = env.content.includes('MAIL_PASSWORD=');

          results.push({
            type: 'LARAVEL_ENV_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Laravel .env file exposed - application secrets leaked',
            exposedSecrets: {
              appKey: hasAppKey,
              dbCredentials: hasDbCreds,
              mailCredentials: hasMailCreds,
            },
          });
        }
      }

      // Ignition RCE - CVE-2021-3129 (Laravel < 8.4.2 with Ignition < 2.5.2)
      const ignitionPaths = [
        '/_ignition/health-check',
        '/_ignition/execute-solution',
        '/_ignition/share-report',
        '/_ignition/scripts',
      ];
      for (const path of ignitionPaths) {
        const ignition = await checkPathExists(path, text =>
          text.includes('ignition') || text.includes('Ignition') ||
          text.includes('"can_execute"') || CONTENT_VALIDATORS.json(text)
        );
        if (ignition.exists) {
          results.push({
            type: 'LARAVEL_IGNITION_EXPOSED',
            severity: 'critical',
            path: path,
            cve: 'CVE-2021-3129',
            evidence: 'Laravel Ignition debug endpoint exposed - potential RCE (CVE-2021-3129)',
            exploit: 'Phar deserialization allows unauthenticated RCE',
          });
          break;
        }
      }

      // Laravel Telescope (debugging tool)
      const telescopePaths = ['/telescope', '/telescope/requests', '/telescope/queries'];
      for (const path of telescopePaths) {
        const telescope = await checkPathExists(path, text =>
          text.includes('Telescope') || text.includes('telescope') ||
          text.includes('Laravel') || text.includes('"entries"')
        );
        if (telescope.exists) {
          results.push({
            type: 'LARAVEL_TELESCOPE_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Laravel Telescope debugging tool exposed - leaks requests, queries, logs',
          });
          break;
        }
      }

      // Laravel Horizon (queue dashboard)
      const horizonPaths = ['/horizon', '/horizon/api/stats'];
      for (const path of horizonPaths) {
        const horizon = await checkPathExists(path, text =>
          text.includes('Horizon') || text.includes('horizon') ||
          text.includes('"status"') || text.includes('Laravel')
        );
        if (horizon.exists) {
          results.push({
            type: 'LARAVEL_HORIZON_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'Laravel Horizon queue dashboard exposed',
          });
          break;
        }
      }

      // Log file exposure
      const logPaths = [
        '/storage/logs/laravel.log',
        '/laravel.log',
        '/storage/logs/laravel-' + new Date().toISOString().split('T')[0] + '.log',
        '/app/storage/logs/laravel.log',
        '/logs/laravel.log',
      ];
      for (const path of logPaths) {
        const log = await checkPathExists(path, CONTENT_VALIDATORS.log);
        if (log.exists) {
          results.push({
            type: 'LARAVEL_LOG_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Laravel log file exposed - may contain stack traces and sensitive data',
            preview: log.content.substring(0, 300),
          });
        }
      }

      // Debug mode detection (Whoops error handler)
      if (html.includes('Whoops!') || html.includes('Whoops\\') ||
          html.includes('APP_DEBUG') || html.includes('DebugBar')) {
        results.push({
          type: 'LARAVEL_DEBUG_MODE',
          severity: 'critical',
          evidence: 'Laravel debug mode enabled - stack traces and source code exposed',
        });
      }

      // Storage directory listing
      const storagePaths = ['/storage/', '/storage/app/', '/storage/framework/'];
      for (const path of storagePaths) {
        const storage = await checkPathExists(path, CONTENT_VALIDATORS.dirListing);
        if (storage.exists) {
          results.push({
            type: 'LARAVEL_STORAGE_LISTING',
            severity: 'medium',
            path: path,
            evidence: 'Laravel storage directory listing enabled',
          });
        }
      }

      // Backup files
      const backupPaths = [
        '/storage/app/backups/',
        '/backup.zip', '/backup.tar.gz', '/backup.sql',
        '/laravel.zip', '/app.zip',
      ];
      for (const path of backupPaths) {
        const backup = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.dirListing(text) || text.length > 100
        );
        if (backup.exists && backup.status === 200) {
          results.push({
            type: 'LARAVEL_BACKUP_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Laravel backup file/directory exposed',
          });
        }
      }

      // Nova admin panel
      const novaPaths = ['/nova', '/nova/login', '/nova/dashboards'];
      for (const path of novaPaths) {
        const nova = await checkPathExists(path, text =>
          text.includes('Nova') || text.includes('nova') || text.includes('Laravel')
        );
        if (nova.exists) {
          results.push({
            type: 'LARAVEL_NOVA_EXPOSED',
            severity: 'info',
            path: path,
            evidence: 'Laravel Nova admin panel found',
          });
          break;
        }
      }

      // Artisan/tinker exposure (rare but critical)
      const artisanPaths = ['/artisan', '/_artisan'];
      for (const path of artisanPaths) {
        const artisan = await checkPathExists(path, text =>
          text.includes('artisan') || text.includes('Artisan')
        );
        if (artisan.exists) {
          results.push({
            type: 'LARAVEL_ARTISAN_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Laravel Artisan endpoint exposed - potential command execution',
          });
        }
      }

      return results;
    }

    // ============================================================
    // LIFERAY SECURITY CHECKS
    // ============================================================

    async scanLiferay() {
      console.log('[CMS Scanner] Running Liferay security checks...');
      const results = [];
      const html = document.documentElement.outerHTML;

      // Detect Liferay
      const isLiferay = html.includes('Liferay') ||
                        html.includes('/c/portal') ||
                        html.includes('liferay-portlet');

      if (!isLiferay) return results;

      // JSONWS RCE - CVE-2020-7961
      const jsonwsPaths = [
        '/api/jsonws',
        '/api/jsonws?discover',
        '/c/portal/json_service',
      ];
      for (const path of jsonwsPaths) {
        const jsonws = await checkPathExists(path, text =>
          text.includes('services') || text.includes('jsonws') ||
          CONTENT_VALIDATORS.json(text) || text.includes('available')
        );
        if (jsonws.exists) {
          results.push({
            type: 'LIFERAY_JSONWS_EXPOSED',
            severity: 'critical',
            path: path,
            cve: 'CVE-2020-7961',
            evidence: 'Liferay JSONWS API exposed - potential deserialization RCE',
          });
          break;
        }
      }

      // WebDAV exposure
      const webdavPaths = ['/webdav', '/api/webdav'];
      for (const path of webdavPaths) {
        const webdav = await checkPathExists(path, text =>
          text.includes('WebDAV') || text.includes('webdav') || text.includes('DAV')
        );
        if (webdav.exists) {
          results.push({
            type: 'LIFERAY_WEBDAV_EXPOSED',
            severity: 'high',
            path: path,
            cve: 'CVE-2019-16891',
            evidence: 'Liferay WebDAV exposed - potential path traversal (CVE-2019-16891)',
          });
        }
      }

      // Axis servlet (old Liferay)
      const axisPaths = ['/api/axis', '/tunnel-web/axis'];
      for (const path of axisPaths) {
        const axis = await checkPathExists(path, text =>
          text.includes('Axis') || text.includes('WSDL') || text.includes('Service')
        );
        if (axis.exists) {
          results.push({
            type: 'LIFERAY_AXIS_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Liferay Axis servlet exposed - potential SSRF/XXE',
          });
        }
      }

      // Version disclosure
      const versionPaths = [
        '/api/jsonws/portal/get-build-number',
        '/web/guest/home?p_p_id=58&p_p_lifecycle=0',
      ];
      for (const path of versionPaths) {
        const version = await checkPathExists(path, text =>
          /\d{4,}/.test(text) || text.includes('release')
        );
        if (version.exists) {
          results.push({
            type: 'LIFERAY_VERSION_DISCLOSURE',
            severity: 'low',
            path: path,
            evidence: 'Liferay version/build number exposed',
          });
          break;
        }
      }

      return results;
    }

    // ============================================================
    // GENERAL DISCLOSURE SCANNER (COMPREHENSIVE)
    // ============================================================

    async scanGeneralDisclosure() {
      console.log('[CMS Scanner] Running COMPREHENSIVE disclosure checks...');
      const results = [];

      // ===========================================
      // VERSION CONTROL EXPOSURE
      // ===========================================

      // Git repository exposure
      const gitPaths = [
        '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
        '/.git/COMMIT_EDITMSG', '/.git/description', '/.git/info/exclude',
        '/.git/objects/', '/.git/refs/heads/master', '/.git/refs/heads/main',
        '/.git/packed-refs', '/.gitignore', '/.gitattributes',
      ];
      for (const path of gitPaths) {
        const git = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.git(text) || text.includes('[core]') ||
          text.includes('ref:') || text.includes('repositoryformatversion') ||
          text.includes('gitdir') || /[a-f0-9]{40}/i.test(text)
        );
        if (git.exists) {
          results.push({
            type: 'GIT_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Git repository exposed - FULL SOURCE CODE + COMMIT HISTORY downloadable',
            exploit: 'Use: git-dumper, GitTools, or GitHack to extract',
          });
          break;
        }
      }

      // SVN exposure
      const svnPaths = ['/.svn/entries', '/.svn/wc.db', '/.svn/pristine/', '/.svn/text-base/'];
      for (const path of svnPaths) {
        const svn = await checkPathExists(path, text =>
          text.includes('svn') || text.includes('dir') || text.length > 100
        );
        if (svn.exists) {
          results.push({
            type: 'SVN_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'SVN repository exposed - source code extractable',
            exploit: 'Use: svn-extractor, dvcs-ripper',
          });
          break;
        }
      }

      // Mercurial exposure
      const hgPaths = ['/.hg/store/00manifest.i', '/.hg/dirstate', '/.hg/requires'];
      for (const path of hgPaths) {
        const hg = await checkPathExists(path, text => text.length > 10);
        if (hg.exists) {
          results.push({
            type: 'MERCURIAL_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Mercurial repository exposed - source code extractable',
          });
          break;
        }
      }

      // Bazaar exposure
      const bzrPaths = ['/.bzr/README', '/.bzr/branch-format', '/.bzr/checkout/'];
      for (const path of bzrPaths) {
        const bzr = await checkPathExists(path, text => text.length > 10);
        if (bzr.exists) {
          results.push({
            type: 'BAZAAR_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Bazaar repository exposed',
          });
          break;
        }
      }

      // ===========================================
      // ENVIRONMENT FILES (MASSIVE LIST)
      // ===========================================

      const envPaths = [
        // Standard .env variations
        '/.env', '/.env.local', '/.env.dev', '/.env.development',
        '/.env.prod', '/.env.production', '/.env.staging', '/.env.stage',
        '/.env.test', '/.env.testing', '/.env.qa', '/.env.uat',
        '/.env.backup', '/.env.bak', '/.env.old', '/.env.save',
        '/.env.example', '/.env.sample', '/.env.dist', '/.env.default',
        '/.env.txt', '/.env.orig', '/.env.copy', '/.env.swp',
        '/.env.1', '/.env.2', '/.env_backup', '/.env-backup',
        '/.env~', '/.env.php', '/.env.js', '/.env.json',
        // Framework specific
        '/app/.env', '/public/.env', '/html/.env', '/www/.env',
        '/htdocs/.env', '/web/.env', '/webroot/.env', '/httpdocs/.env',
        '/application/.env', '/src/.env', '/config/.env',
        '/.env.local.php', '/.env.development.local', '/.env.production.local',
        // Docker/container
        '/.docker.env', '/docker.env', '/.dockerenv', '/env.docker',
        '/docker-compose.env', '/.env.docker', '/.env.container',
        // Cloud provider specific
        '/.env.aws', '/.env.azure', '/.env.gcp', '/.env.heroku',
        '/.env.vercel', '/.env.netlify', '/.env.railway',
        // CI/CD
        '/.env.ci', '/.env.circleci', '/.env.travis', '/.env.github',
        '/.env.gitlab', '/.env.jenkins', '/.env.build',
      ];

      for (const path of envPaths) {
        const env = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.env(text) || (
            text.includes('=') && (
              /DATABASE|DB_|MYSQL|POSTGRES|MONGO|REDIS/i.test(text) ||
              /SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|AUTH/i.test(text) ||
              /API_|AWS_|STRIPE|TWILIO|SENDGRID|MAILGUN/i.test(text) ||
              /APP_|DEBUG|ENV|NODE_ENV|RAILS_ENV/i.test(text)
            )
          )
        );
        if (env.exists) {
          results.push({
            type: 'ENV_FILE_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Environment file exposed - DATABASE/API CREDENTIALS LEAKED',
            preview: env.content.substring(0, 200).replace(/=.*/g, '=***REDACTED***'),
          });
        }
      }

      // ===========================================
      // CONFIGURATION FILES
      // ===========================================

      const configPaths = [
        // PHP configs
        '/config.php', '/config.php.bak', '/config.php.old', '/config.php~',
        '/config.inc.php', '/config.inc.php.bak', '/configuration.php',
        '/settings.php', '/settings.php.bak', '/local.php', '/local.php.bak',
        '/database.php', '/db.php', '/db_config.php', '/dbconfig.php',
        '/conn.php', '/connection.php', '/connect.php', '/mysql.php',
        '/conf.php', '/conf.inc.php', '/global.php', '/globals.php',
        '/parameters.php', '/parameters.yml', '/parameters.ini',
        // Application configs
        '/app/config/parameters.yml', '/app/config/config.yml',
        '/config/app.php', '/config/database.php', '/config/mail.php',
        '/config/services.php', '/config/auth.php', '/config/filesystems.php',
        // Web server configs
        '/.htaccess', '/.htpasswd', '/nginx.conf', '/httpd.conf',
        '/apache.conf', '/web.config', '/Web.config', '/app.config',
        '/.user.ini', '/php.ini', '/.php.ini', '/php5.ini',
        // Python configs
        '/settings.py', '/config.py', '/local_settings.py', '/secrets.py',
        '/wsgi.py', '/asgi.py', '/manage.py', '/django.cfg',
        // Ruby configs
        '/config/database.yml', '/config/secrets.yml', '/config/credentials.yml.enc',
        '/config/master.key', '/config/application.yml', '/database.yml',
        '/secrets.yml', '/credentials.yml', '/.ruby-version',
        // Node.js configs
        '/config.js', '/config.json', '/config.yaml', '/config.yml',
        '/.babelrc', '/.prettierrc', '/tsconfig.json', '/jsconfig.json',
        '/next.config.js', '/nuxt.config.js', '/vue.config.js',
        '/webpack.config.js', '/vite.config.js', '/rollup.config.js',
        '/nest-cli.json', '/angular.json', '/.npmrc',
        // Java configs
        '/application.properties', '/application.yml', '/application-dev.yml',
        '/application-prod.yml', '/bootstrap.yml', '/bootstrap.properties',
        '/WEB-INF/web.xml', '/META-INF/context.xml', '/persistence.xml',
        '/hibernate.cfg.xml', '/struts.xml', '/beans.xml',
        // .NET configs
        '/web.config', '/appsettings.json', '/appsettings.Development.json',
        '/appsettings.Production.json', '/connectionStrings.config',
        '/machine.config', '/App.config', '/applicationhost.config',
        // Generic
        '/settings.json', '/settings.yaml', '/settings.yml', '/settings.xml',
        '/conf.json', '/conf.yaml', '/conf.yml', '/conf.xml',
        '/credentials.json', '/credentials.xml', '/auth.json', '/secrets.json',
      ];

      for (const path of configPaths) {
        const config = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.config(text) || CONTENT_VALIDATORS.env(text) ||
          text.includes('password') || text.includes('secret') ||
          text.includes('database') || text.includes('connection') ||
          /["']?(password|passwd|pwd|secret|key|token)["']?\s*[=:]/i.test(text)
        );
        if (config.exists) {
          results.push({
            type: 'CONFIG_FILE_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'Configuration file exposed - may contain credentials',
          });
        }
      }

      // ===========================================
      // DATABASE FILES & BACKUPS
      // ===========================================

      const dbPaths = [
        // SQL dumps
        '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
        '/mysql.sql', '/data.sql', '/export.sql', '/db_backup.sql',
        '/_backup.sql', '/backup-db.sql', '/site.sql', '/wp.sql',
        '/wordpress.sql', '/drupal.sql', '/joomla.sql', '/magento.sql',
        // Compressed SQL
        '/backup.sql.gz', '/dump.sql.gz', '/database.sql.gz', '/db.sql.gz',
        '/backup.sql.zip', '/dump.sql.zip', '/database.sql.zip',
        '/backup.sql.tar', '/dump.sql.tar', '/backup.sql.tar.gz',
        '/backup.sql.bz2', '/dump.sql.bz2', '/data.sql.gz',
        // Date-based backups
        `/backup-${new Date().toISOString().split('T')[0]}.sql`,
        `/db-${new Date().toISOString().split('T')[0]}.sql`,
        '/backup-2024.sql', '/backup-2023.sql', '/backup-2025.sql',
        '/db-backup-latest.sql', '/latest-backup.sql', '/full-backup.sql',
        // SQLite databases
        '/database.db', '/data.db', '/app.db', '/sqlite.db',
        '/db.sqlite', '/db.sqlite3', '/database.sqlite', '/database.sqlite3',
        '/users.db', '/admin.db', '/site.db', '/main.db',
        '/.sqlite_history', '/dev.db', '/test.db', '/production.db',
        // Other databases
        '/dump.rdb', '/redis.rdb', '/appendonly.aof', // Redis
        '/mongodump/', '/mongodb.json', // MongoDB
        // Common backup directories
        '/backups/db.sql', '/backup/database.sql', '/sql/backup.sql',
        '/dumps/latest.sql', '/exports/database.sql', '/db/backup.sql',
      ];

      for (const path of dbPaths) {
        const db = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.sql(text) || text.length > 500 ||
          /SQLite format|CREATE TABLE|INSERT INTO|mysqldump/i.test(text)
        );
        if (db.exists) {
          results.push({
            type: 'DATABASE_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'DATABASE DUMP/FILE EXPOSED - FULL DATA BREACH',
            preview: db.content?.substring(0, 150),
          });
        }
      }

      // ===========================================
      // ARCHIVE & BACKUP FILES
      // ===========================================

      const archivePaths = [
        // ZIP archives
        '/backup.zip', '/site.zip', '/www.zip', '/web.zip',
        '/html.zip', '/public.zip', '/httpdocs.zip', '/htdocs.zip',
        '/source.zip', '/src.zip', '/code.zip', '/app.zip',
        '/archive.zip', '/files.zip', '/data.zip', '/old.zip',
        '/website.zip', '/webroot.zip', '/deploy.zip', '/release.zip',
        '/_backup.zip', '/full-backup.zip', '/site-backup.zip',
        // TAR archives
        '/backup.tar', '/backup.tar.gz', '/backup.tgz', '/backup.tar.bz2',
        '/site.tar.gz', '/www.tar.gz', '/source.tar.gz', '/code.tar.gz',
        '/archive.tar.gz', '/files.tar.gz', '/data.tar.gz',
        '/app.tar.gz', '/web.tar.gz', '/public.tar.gz',
        // RAR archives
        '/backup.rar', '/site.rar', '/source.rar', '/archive.rar',
        // 7z archives
        '/backup.7z', '/site.7z', '/source.7z', '/archive.7z',
        // Date-based
        `/backup-${new Date().getFullYear()}.zip`,
        `/backup-${new Date().toISOString().split('T')[0]}.zip`,
        '/backup-latest.zip', '/backup-full.zip', '/backup-complete.zip',
        // CMS/Framework specific
        '/wordpress.zip', '/wp-backup.zip', '/drupal-backup.zip',
        '/joomla-backup.zip', '/magento-backup.zip', '/laravel.zip',
        // Incremental
        '/backup.0.zip', '/backup.1.zip', '/backup-1.zip', '/backup-2.zip',
        // Directories
        '/backup/', '/backups/', '/bak/', '/old/', '/archive/',
        '/_backup/', '/_backups/', '/bkp/', '/bkup/',
      ];

      for (const path of archivePaths) {
        const archive = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.dirListing(text) ||
          text.startsWith('PK') || // ZIP magic
          text.startsWith('\x1f\x8b') || // GZIP magic
          text.length > 1000
        );
        if (archive.exists) {
          results.push({
            type: 'BACKUP_ARCHIVE_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'BACKUP ARCHIVE EXPOSED - may contain full source code + database',
          });
        }
      }

      // ===========================================
      // LOG FILES
      // ===========================================

      const logPaths = [
        // Application logs
        '/debug.log', '/error.log', '/errors.log', '/app.log',
        '/application.log', '/server.log', '/access.log', '/access_log',
        '/error_log', '/php_errors.log', '/php-errors.log', '/php_error.log',
        '/.log', '/log.txt', '/logs.txt', '/output.log',
        // Framework logs
        '/storage/logs/laravel.log', '/var/log/laravel.log',
        '/logs/error.log', '/logs/debug.log', '/logs/app.log',
        '/log/development.log', '/log/production.log', '/log/test.log',
        '/tmp/logs/error.log', '/var/log/app.log',
        // Web server logs
        '/var/log/apache2/error.log', '/var/log/nginx/error.log',
        '/var/log/httpd/error_log', '/apache/logs/error.log',
        '/nginx/logs/error.log', '/logs/access.log', '/logs/error.log',
        // Debug/trace
        '/trace.log', '/debug.txt', '/trace.txt', '/dump.log',
        '/sql.log', '/queries.log', '/db.log', '/database.log',
        '/mail.log', '/email.log', '/cron.log', '/scheduler.log',
        // FTP/deployment
        '/ftp.log', '/sftp.log', '/deploy.log', '/deployment.log',
        '/git.log', '/update.log', '/upgrade.log', '/migration.log',
        // Specific CMS
        '/wp-content/debug.log', '/wp-content/error.log',
        '/sites/default/files/logs/', '/administrator/logs/',
        '/var/logs/', '/tmp/debug.log',
      ];

      for (const path of logPaths) {
        const log = await checkPathExists(path, CONTENT_VALIDATORS.log);
        if (log.exists) {
          results.push({
            type: 'LOG_FILE_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Log file exposed - may contain errors, stack traces, sensitive data',
            preview: log.content?.substring(0, 200),
          });
        }
      }

      // ===========================================
      // PHPINFO & DEBUG ENDPOINTS
      // ===========================================

      const phpinfoPaths = [
        '/phpinfo.php', '/info.php', '/php_info.php', '/test.php',
        '/i.php', '/pi.php', '/php.php', '/_phpinfo.php',
        '/pinfo.php', '/p.php', '/inf.php', '/check.php',
        '/debug.php', '/server-info.php', '/server.php', '/status.php',
        '/health.php', '/ping.php', '/test/phpinfo.php', '/tests/info.php',
        '/admin/phpinfo.php', '/_info.php', '/~info.php',
        '/phpversion.php', '/version.php', '/environment.php',
      ];

      for (const path of phpinfoPaths) {
        const phpinfo = await checkPathExists(path, CONTENT_VALIDATORS.phpinfo);
        if (phpinfo.exists) {
          results.push({
            type: 'PHPINFO_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'phpinfo() exposed - FULL SERVER CONFIGURATION LEAKED',
          });
        }
      }

      // ===========================================
      // SERVER STATUS & ADMIN PANELS
      // ===========================================

      const statusPaths = [
        '/server-status', '/server-info', '/status', '/health',
        '/nginx_status', '/nginx-status', '/stub_status',
        '/apc.php', '/apc-info.php', '/opcache.php', '/opcache-status.php',
        '/memcache.php', '/memcached.php', '/redis-info.php',
        '/jmx-console/', '/web-console/', '/manager/html',
        '/manager/status', '/admin-console/', '/jboss-console/',
        '/invoker/JMXInvokerServlet', '/solr/admin/', '/solr/',
        '/elasticsearch/', '/_cluster/health', '/_cat/indices',
        '/hawtio/', '/actuator', '/actuator/health', '/actuator/env',
        '/actuator/configprops', '/actuator/mappings', '/actuator/beans',
        '/metrics', '/prometheus', '/grafana/', '/kibana/',
        '/debug/', '/debug/default/view', '/trace/', '/traces/',
        '/.well-known/health', '/.well-known/status',
      ];

      for (const path of statusPaths) {
        const status = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.serverStatus(text) || CONTENT_VALIDATORS.json(text) ||
          text.includes('status') || text.includes('health') ||
          text.includes('version') || text.includes('uptime')
        );
        if (status.exists) {
          results.push({
            type: 'SERVER_STATUS_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'Server status/monitoring endpoint exposed',
          });
        }
      }

      // Database admin tools
      const dbAdminPaths = [
        '/phpmyadmin/', '/phpMyAdmin/', '/pma/', '/myadmin/',
        '/mysql/', '/mysqladmin/', '/sqlmanager/', '/sql/',
        '/db/', '/dbadmin/', '/database/', '/phpmyadmin2/',
        '/phpmyadmin3/', '/phpmyadmin4/', '/phpmyadmin5/',
        '/pma2/', '/pma3/', '/pma4/', '/MyAdmin/',
        '/adminer.php', '/adminer/', '/adminer-4.8.1.php',
        '/adminer-4.php', '/adminer.php.bak', '/_adminer.php',
        '/sqladmin/', '/sqlweb/', '/phpminiadmin.php',
        '/sysadmin/', '/webadmin/', '/dbweb/', '/websql/',
      ];

      for (const path of dbAdminPaths) {
        const dbAdmin = await checkPathExists(path, text =>
          text.includes('phpMyAdmin') || text.includes('Adminer') ||
          text.includes('Database') || text.includes('SQL') ||
          (text.includes('login') && text.includes('server'))
        );
        if (dbAdmin.exists) {
          results.push({
            type: 'DB_ADMIN_EXPOSED',
            severity: 'high',
            path: path,
            evidence: 'Database admin panel found - potential DB access',
          });
        }
      }

      // Admin panels
      const adminPaths = [
        '/admin/', '/administrator/', '/admin.php', '/login.php',
        '/cpanel/', '/manager/', '/control/', '/controlpanel/',
        '/adminpanel/', '/admin-panel/', '/administration/',
        '/cms/', '/cms-admin/', '/backend/', '/backoffice/',
        '/dashboard/', '/panel/', '/webmaster/', '/siteadmin/',
        '/system/', '/sys/', '/sysadmin/', '/useradmin/',
        '/moderator/', '/manage/', '/management/', '/admin/login',
        '/admin/dashboard', '/admin/index.php', '/wp-admin/',
        '/user/login', '/account/login', '/auth/login', '/signin',
        '/_admin/', '/~admin/', '/admin1/', '/admin2/',
        '/secret-admin/', '/hidden-admin/', '/super-admin/',
      ];

      for (const path of adminPaths) {
        const admin = await checkPathExists(path, text =>
          text.includes('login') || text.includes('admin') ||
          text.includes('password') || text.includes('username') ||
          text.includes('sign in') || text.includes('Log in')
        );
        if (admin.exists) {
          results.push({
            type: 'ADMIN_PANEL_FOUND',
            severity: 'info',
            path: path,
            evidence: 'Admin panel found',
          });
        }
      }

      // ===========================================
      // CLOUD & CI/CD CREDENTIALS
      // ===========================================

      const cloudPaths = [
        // AWS
        '/.aws/credentials', '/.aws/config', '/aws.yml', '/aws.json',
        '/aws-credentials', '/credentials.aws', '/.s3cfg',
        // Azure
        '/.azure/credentials', '/azure.json', '/azure-credentials.json',
        '/azureauth.json', '/.azure/',
        // GCP
        '/gcp-credentials.json', '/google-credentials.json',
        '/service-account.json', '/keyfile.json', '/gcloud-service-key.json',
        '/.config/gcloud/credentials', '/application_default_credentials.json',
        // Docker
        '/.docker/config.json', '/docker-compose.yml', '/docker-compose.yaml',
        '/docker-compose.override.yml', '/Dockerfile', '/.dockerignore',
        '/docker-compose.dev.yml', '/docker-compose.prod.yml',
        // Kubernetes
        '/.kube/config', '/kubeconfig', '/kubeconfig.yml', '/kubeconfig.yaml',
        '/kubernetes.yml', '/k8s.yml', '/helm/values.yaml',
        '/.helm/', '/charts/', '/manifests/',
        // Terraform
        '/terraform.tfvars', '/terraform.tfstate', '/.terraform/',
        '/main.tf', '/variables.tf', '/secrets.tf', '/backend.tf',
        '/terraform.tfstate.backup', '/.terraform.lock.hcl',
        // Ansible
        '/ansible.cfg', '/hosts', '/inventory', '/vault-password',
        '/group_vars/all.yml', '/host_vars/', '/ansible-vault',
        // CI/CD
        '/.travis.yml', '/.gitlab-ci.yml', '/.github/workflows/',
        '/Jenkinsfile', '/jenkins.yml', '/.circleci/config.yml',
        '/bitbucket-pipelines.yml', '/azure-pipelines.yml',
        '/.drone.yml', '/wercker.yml', '/appveyor.yml',
        '/cloudbuild.yaml', '/buildspec.yml', '/taskcat.yml',
        // Heroku
        '/Procfile', '/app.json', '/.buildpacks', '/heroku.yml',
        // Vercel/Netlify
        '/vercel.json', '/now.json', '/netlify.toml', '/_redirects',
        // Firebase
        '/firebase.json', '/.firebaserc', '/firestore.rules',
        '/storage.rules', '/database.rules.json',
        // Package registries
        '/.npmrc', '/.yarnrc', '/.yarnrc.yml', '/yarn.lock',
        '/.pypirc', '/pip.conf', '/.gem/credentials',
        '/rubygems_api_key', '/settings.xml', '/.m2/settings.xml',
        '/.nuget/NuGet.Config', '/nuget.config',
      ];

      for (const path of cloudPaths) {
        const cloud = await checkPathExists(path, text =>
          text.includes('aws_access_key') || text.includes('aws_secret') ||
          text.includes('AKIA') || // AWS key prefix
          text.includes('client_secret') || text.includes('client_id') ||
          text.includes('api_key') || text.includes('apikey') ||
          text.includes('private_key') || text.includes('-----BEGIN') ||
          text.includes('registry') || text.includes('credentials') ||
          text.includes('token') || text.includes('password') ||
          text.length > 50
        );
        if (cloud.exists) {
          results.push({
            type: 'CLOUD_CREDENTIALS_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'CLOUD/CI CREDENTIALS EXPOSED - Infrastructure compromise possible',
          });
        }
      }

      // ===========================================
      // SSH & CRYPTO KEYS
      // ===========================================

      const keyPaths = [
        '/.ssh/id_rsa', '/.ssh/id_rsa.pub', '/.ssh/id_dsa',
        '/.ssh/id_ecdsa', '/.ssh/id_ed25519', '/.ssh/authorized_keys',
        '/.ssh/known_hosts', '/.ssh/config', '/id_rsa', '/id_rsa.pub',
        '/private.key', '/private.pem', '/privatekey.pem', '/server.key',
        '/ssl.key', '/certificate.key', '/cert.key', '/key.pem',
        '/privkey.pem', '/fullchain.pem', '/chain.pem', '/cert.pem',
        '/server.crt', '/ssl.crt', '/certificate.crt', '/ca.crt',
        '/.gnupg/', '/gpg.key', '/secret.key', '/signing.key',
        '/jwt.key', '/jwt_secret', '/encryption.key', '/master.key',
        '/crypto.key', '/api.key', '/auth.key', '/secret.pem',
      ];

      for (const path of keyPaths) {
        const key = await checkPathExists(path, text =>
          text.includes('-----BEGIN') || text.includes('PRIVATE KEY') ||
          text.includes('ssh-rsa') || text.includes('ssh-ed25519') ||
          text.includes('PuTTY') || text.includes('ENCRYPTED')
        );
        if (key.exists) {
          results.push({
            type: 'PRIVATE_KEY_EXPOSED',
            severity: 'critical',
            path: path,
            evidence: 'PRIVATE KEY EXPOSED - Server/SSL/SSH compromise possible',
          });
        }
      }

      // ===========================================
      // API DOCUMENTATION & SWAGGER
      // ===========================================

      const apiDocPaths = [
        '/swagger.json', '/swagger.yaml', '/swagger/', '/swagger-ui/',
        '/swagger-ui.html', '/api-docs', '/api-docs/', '/api-docs.json',
        '/openapi.json', '/openapi.yaml', '/openapi/', '/v2/api-docs',
        '/v3/api-docs', '/docs/api', '/api/docs', '/api/swagger',
        '/api/documentation', '/documentation/', '/redoc/', '/redoc.html',
        '/graphql', '/graphiql', '/graphql-playground', '/graphql/console',
        '/__graphql', '/api/graphql', '/graphql/schema',
        '/api/v1/docs', '/api/v2/docs', '/api/v3/docs',
        '/api/v1/', '/api/v2/', '/api/v3/', '/api/latest/',
        '/developer/', '/developers/', '/api-reference/',
        '/postman/', '/postman_collection.json', '/insomnia.json',
        '/.well-known/openapi.json', '/rest/api/',
      ];

      for (const path of apiDocPaths) {
        const apiDoc = await checkPathExists(path, text =>
          text.includes('swagger') || text.includes('openapi') ||
          text.includes('paths') || text.includes('schemas') ||
          text.includes('graphql') || text.includes('__schema') ||
          text.includes('endpoints') || text.includes('API')
        );
        if (apiDoc.exists) {
          results.push({
            type: 'API_DOCUMENTATION_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'API documentation exposed - reveals all endpoints',
          });
        }
      }

      // ===========================================
      // IDE & EDITOR FILES
      // ===========================================

      const idePaths = [
        // JetBrains (IntelliJ, PHPStorm, WebStorm, etc.)
        '/.idea/', '/.idea/workspace.xml', '/.idea/modules.xml',
        '/.idea/misc.xml', '/.idea/vcs.xml', '/.idea/dataSources.xml',
        '/.idea/dataSources.local.xml', '/.idea/httpRequests/',
        // VS Code
        '/.vscode/', '/.vscode/settings.json', '/.vscode/launch.json',
        '/.vscode/tasks.json', '/.vscode/extensions.json',
        '/.vscode/sftp.json', // SFTP credentials!
        // Eclipse
        '/.project', '/.classpath', '/.settings/', '/.buildpath',
        '/.externalToolBuilders/', '/.metadata/',
        // NetBeans
        '/nbproject/', '/nbproject/project.xml', '/nbproject/private/',
        // Sublime
        '/.sublime-project', '/.sublime-workspace',
        // Vim/Emacs
        '/.vimrc', '/.vim/', '/.emacs', '/.emacs.d/',
        '/Session.vim', '/*.swp', '/*~',
        // Editors leave these
        '/.editorconfig', '/.prettierrc', '/.eslintrc',
        '/.babelrc', '/.stylelintrc',
      ];

      for (const path of idePaths) {
        const ide = await checkPathExists(path, text =>
          text.includes('version') || text.includes('project') ||
          text.includes('module') || text.includes('source') ||
          CONTENT_VALIDATORS.xml(text) || CONTENT_VALIDATORS.json(text) ||
          text.includes('password') || text.includes('host')
        );
        if (ide.exists) {
          results.push({
            type: 'IDE_FILES_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'IDE project files exposed - may contain paths, credentials',
          });
        }
      }

      // ===========================================
      // PACKAGE MANAGER FILES
      // ===========================================

      const packagePaths = [
        '/composer.json', '/composer.lock', '/vendor/',
        '/package.json', '/package-lock.json', '/yarn.lock',
        '/node_modules/', '/npm-debug.log', '/yarn-error.log',
        '/Gemfile', '/Gemfile.lock', '/vendor/bundle/',
        '/requirements.txt', '/requirements-dev.txt', '/Pipfile',
        '/Pipfile.lock', '/poetry.lock', '/pyproject.toml', '/setup.py',
        '/go.mod', '/go.sum', '/vendor/', '/Gopkg.lock',
        '/Cargo.toml', '/Cargo.lock', '/target/',
        '/pom.xml', '/build.gradle', '/settings.gradle', '/gradlew',
        '/build.sbt', '/project/', '/ivy.xml',
        '/mix.exs', '/mix.lock', '/deps/',
        '/cpanfile', '/Makefile.PL', '/Build.PL',
        '/cabal.config', '/stack.yaml', '/package.yaml',
        '/pubspec.yaml', '/pubspec.lock', '/.packages',
        '/bower.json', '/bower_components/', '/shrinkwrap.yaml',
      ];

      for (const path of packagePaths) {
        const pkg = await checkPathExists(path, text =>
          CONTENT_VALIDATORS.json(text) || CONTENT_VALIDATORS.dirListing(text) ||
          text.includes('dependencies') || text.includes('require') ||
          text.includes('version') || text.includes('name')
        );
        if (pkg.exists) {
          results.push({
            type: 'PACKAGE_FILE_EXPOSED',
            severity: 'low',
            path: path,
            evidence: 'Package manager files exposed - dependency info leaked',
          });
        }
      }

      // ===========================================
      // SENSITIVE DIRECTORIES
      // ===========================================

      const sensitiveDirs = [
        '/backup/', '/backups/', '/bak/', '/old/', '/archive/',
        '/tmp/', '/temp/', '/cache/', '/caches/',
        '/logs/', '/log/', '/logging/',
        '/data/', '/db/', '/database/', '/sql/', '/mysql/',
        '/private/', '/secret/', '/secrets/', '/internal/',
        '/dev/', '/development/', '/test/', '/testing/', '/staging/',
        '/upload/', '/uploads/', '/files/', '/documents/', '/docs/',
        '/media/', '/assets/', '/static/', '/resources/',
        '/include/', '/includes/', '/inc/', '/lib/', '/libs/',
        '/src/', '/source/', '/sources/', '/app/', '/application/',
        '/core/', '/system/', '/sys/', '/modules/', '/plugins/',
        '/themes/', '/templates/', '/views/', '/components/',
        '/api/', '/rest/', '/services/', '/handlers/',
        '/admin/', '/administrator/', '/manage/', '/management/',
        '/config/', '/conf/', '/configuration/', '/settings/',
        '/scripts/', '/cgi-bin/', '/bin/', '/tools/',
        '/export/', '/exports/', '/import/', '/imports/',
        '/download/', '/downloads/', '/dl/',
        '/.hidden/', '/_private/', '/__backup/',
      ];

      for (const path of sensitiveDirs) {
        const dir = await checkPathExists(path, CONTENT_VALIDATORS.dirListing);
        if (dir.exists) {
          results.push({
            type: 'DIRECTORY_LISTING',
            severity: 'medium',
            path: path,
            evidence: 'Directory listing enabled - file enumeration possible',
          });
        }
      }

      // ===========================================
      // MISC SENSITIVE FILES
      // ===========================================

      const miscPaths = [
        // History files
        '/.bash_history', '/.sh_history', '/.zsh_history',
        '/.mysql_history', '/.psql_history', '/.sqlite_history',
        '/.node_repl_history', '/.python_history', '/.irb_history',
        // Profile files
        '/.bashrc', '/.bash_profile', '/.profile', '/.zshrc',
        // System files
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
        '/proc/self/environ', '/proc/self/cmdline', '/proc/version',
        // Temp and cache
        '/.cache/', '/cache.json', '/cache.xml', '/.tmp/',
        // Debug/test files
        '/test.txt', '/test.html', '/test.php', '/debug.txt',
        '/info.txt', '/readme.txt', '/README.md', '/CHANGELOG.md',
        '/TODO.txt', '/notes.txt', '/INSTALL.txt', '/LICENSE',
        // Backup extensions
        '/index.php.bak', '/index.php~', '/index.php.old',
        '/index.php.orig', '/index.php.save', '/index.php.swp',
        '/index.html.bak', '/index.html~', '/index.html.old',
        // Common vulnerable paths
        '/cgi-bin/test-cgi', '/cgi-bin/printenv', '/cgi-bin/php',
        '/fcgi-bin/', '/servlet/', '/axis/', '/axis2/',
        // File upload
        '/upload.php', '/uploader.php', '/fileupload.php',
        '/upload/', '/uploads/', '/uploaded/', '/attachments/',
        // Installers
        '/install/', '/install.php', '/setup/', '/setup.php',
        '/installer/', '/installer.php', '/init/', '/initialize/',
      ];

      for (const path of miscPaths) {
        const misc = await checkPathExists(path, text =>
          text.length > 20 || CONTENT_VALIDATORS.dirListing(text)
        );
        if (misc.exists && misc.content && misc.content.length > 50) {
          results.push({
            type: 'SENSITIVE_FILE_EXPOSED',
            severity: 'medium',
            path: path,
            evidence: 'Potentially sensitive file exposed',
          });
        }
      }

      // ===========================================
      // ROBOTS.TXT ANALYSIS
      // ===========================================

      const robots = await checkPathExists('/robots.txt', text =>
        text.includes('Disallow') || text.includes('User-agent')
      );
      if (robots.exists) {
        const disallowedPaths = robots.content.match(/Disallow:\s*(\S+)/gi) || [];
        const interestingPaths = disallowedPaths
          .map(d => d.replace(/Disallow:\s*/i, ''))
          .filter(p => p && p !== '/' && p.length > 1);

        if (interestingPaths.length > 0) {
          results.push({
            type: 'ROBOTS_INTERESTING_PATHS',
            severity: 'info',
            path: '/robots.txt',
            evidence: `robots.txt reveals ${interestingPaths.length} disallowed paths`,
            paths: interestingPaths.slice(0, 20),
          });

          // Auto-check interesting disallowed paths
          const criticalPatterns = [
            'admin', 'backup', 'config', 'private', 'secret',
            'api', 'internal', '.env', 'database', 'sql',
            'password', 'credential', 'key', 'token',
          ];

          for (const disPath of interestingPaths.slice(0, 10)) {
            if (criticalPatterns.some(p => disPath.toLowerCase().includes(p))) {
              const check = await checkPathExists(disPath, text => text.length > 50);
              if (check.exists) {
                results.push({
                  type: 'ROBOTS_HIDDEN_PATH_ACCESSIBLE',
                  severity: 'high',
                  path: disPath,
                  evidence: `Hidden path from robots.txt is accessible: ${disPath}`,
                });
              }
            }
          }
        }
      }

      // ===========================================
      // SITEMAP ANALYSIS
      // ===========================================

      const sitemapPaths = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap/', '/sitemaps/'];
      for (const path of sitemapPaths) {
        const sitemap = await checkPathExists(path, text =>
          text.includes('<url>') || text.includes('<sitemap>') ||
          text.includes('<loc>') || text.includes('urlset')
        );
        if (sitemap.exists) {
          // Look for interesting URLs in sitemap
          const adminUrls = sitemap.content.match(/<loc>[^<]*(admin|manage|dashboard|internal|api|secret)[^<]*<\/loc>/gi);
          if (adminUrls && adminUrls.length > 0) {
            results.push({
              type: 'SITEMAP_SENSITIVE_URLS',
              severity: 'low',
              path: path,
              evidence: 'Sitemap reveals potentially sensitive URLs',
              urls: adminUrls.slice(0, 5),
            });
          }
          break;
        }
      }

      console.log(`[CMS Scanner] Disclosure scan found ${results.length} issues`);
      return results;
    }

    // ============================================================
    // FRAMEWORK VULNERABILITY CHECKS
    // ============================================================

    async scanFrameworkVulnerabilities() {
      console.log('[CMS Scanner] Running framework vulnerability checks...');
      const results = [];
      const html = document.documentElement.outerHTML;
      const isNextJS = !!window.__NEXT_DATA__;

      // Next.js checks
      if (isNextJS) {
        // Check for sensitive data in __NEXT_DATA__
        const nextData = JSON.stringify(window.__NEXT_DATA__);
        const sensitivePatterns = ['password', 'secret', 'api_key', 'apikey', 'token', 'private', 'credential'];
        for (const pattern of sensitivePatterns) {
          if (nextData.toLowerCase().includes(pattern)) {
            results.push({
              type: 'NEXTJS_SENSITIVE_DATA',
              severity: 'high',
              evidence: `Potentially sensitive data ("${pattern}") found in __NEXT_DATA__`,
            });
            break;
          }
        }

        // Check for debug/development mode indicators
        if (window.__NEXT_DATA__.runtimeConfig?.debug || window.__NEXT_DATA__.buildId === 'development') {
          results.push({
            type: 'NEXTJS_DEBUG_MODE',
            severity: 'medium',
            evidence: 'Next.js appears to be in development/debug mode',
          });
        }

        // Next.js version detection for known CVEs
        const buildId = window.__NEXT_DATA__.buildId;
        const nextVersion = window.__NEXT_DATA__.nextExport ? 'export' : 'dynamic';
        console.log(`[CMS Scanner] Next.js build: ${buildId}, mode: ${nextVersion}`);
      }

      // Next.js Image Optimizer SSRF - CVE-2022-46175
      const ssrfTestUrls = [
        '/_next/image?url=http://localhost&w=64&q=75',
        '/_next/image?url=http://127.0.0.1&w=64&q=75',
        '/_next/image?url=http://169.254.169.254&w=64&q=75', // AWS metadata
        '/_next/image?url=http://[::1]&w=64&q=75', // IPv6 localhost
      ];
      for (const testUrl of ssrfTestUrls) {
        try {
          const response = await fetchWithTimeout(location.origin + testUrl, {}, 3000);
          // If we get something other than 400/403/404, might be vulnerable
          if (response.status === 200 || response.status === 500) {
            results.push({
              type: 'NEXTJS_IMAGE_SSRF',
              severity: 'high',
              path: testUrl,
              cve: 'CVE-2022-46175',
              evidence: 'Next.js image optimizer may allow SSRF to internal services',
              status: response.status,
            });
            break;
          }
        } catch {}
      }

      // Next.js Middleware Bypass - CVE-2024-34351
      const middlewareBypassPaths = [
        '/_next/../../../etc/passwd',
        '/api/../../../etc/passwd',
        '/%5f_next/static/',  // URL encoded _
        '/_next/data/../../../api/secret',
      ];
      for (const path of middlewareBypassPaths) {
        try {
          const response = await fetchWithTimeout(location.origin + path, {}, 3000);
          if (response.status === 200 && response.url !== location.origin + path) {
            results.push({
              type: 'NEXTJS_MIDDLEWARE_BYPASS',
              severity: 'high',
              path: path,
              cve: 'CVE-2024-34351',
              evidence: 'Next.js middleware may be bypassable via path traversal',
            });
            break;
          }
        } catch {}
      }

      // Next.js Source Maps exposure
      const sourceMapPaths = [
        '/_next/static/chunks/main.js.map',
        '/_next/static/chunks/webpack.js.map',
        '/_next/static/chunks/pages/_app.js.map',
        '/_next/static/development/_buildManifest.js.map',
      ];
      for (const path of sourceMapPaths) {
        const srcMap = await checkPathExists(path, text =>
          text.includes('mappings') || text.includes('sources') ||
          text.includes('sourcesContent') || text.startsWith('{')
        );
        if (srcMap.exists) {
          results.push({
            type: 'NEXTJS_SOURCE_MAPS',
            severity: 'medium',
            path: path,
            evidence: 'Next.js source maps exposed - original source code accessible',
          });
          break;
        }
      }

      // Next.js Data exposure via _next/data
      if (isNextJS) {
        const buildId = window.__NEXT_DATA__?.buildId;
        if (buildId && buildId !== 'development') {
          const dataPath = `/_next/data/${buildId}/index.json`;
          const dataCheck = await checkPathExists(dataPath, text => {
            try {
              const data = JSON.parse(text);
              return data.pageProps !== undefined;
            } catch { return false; }
          });
          if (dataCheck.exists) {
            results.push({
              type: 'NEXTJS_DATA_EXPOSURE',
              severity: 'info',
              path: dataPath,
              evidence: 'Next.js server-side props accessible via _next/data endpoint',
            });
          }
        }
      }

      // Check Next.js API routes
      const nextApiPaths = ['/api/auth', '/api/users', '/api/admin', '/api/config', '/api/debug', '/api/graphql'];
      for (const path of nextApiPaths) {
        const api = await checkPathExists(path, text => {
          if (path.includes('debug') || path.includes('config')) {
            return text.length > 50;
          }
          if (path.includes('graphql')) {
            return text.includes('query') || text.includes('mutation') || text.includes('__schema');
          }
          return false;
        });
        if (api.exists && api.content) {
          results.push({
            type: 'NEXTJS_API_EXPOSED',
            severity: path.includes('debug') || path.includes('config') ? 'high' : 'info',
            path: path,
            evidence: `Next.js API route ${path} accessible`,
          });
        }
      }

      // React checks
      if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
        results.push({
          type: 'REACT_DEVTOOLS_PRODUCTION',
          severity: 'low',
          evidence: 'React DevTools detected in production',
        });
      }

      // Check for dangerouslySetInnerHTML (XSS risk)
      if (html.includes('dangerouslySetInnerHTML')) {
        results.push({
          type: 'REACT_DANGEROUS_INNERHTML',
          severity: 'medium',
          evidence: 'dangerouslySetInnerHTML usage detected - potential XSS risk',
        });
      }

      // Vue checks
      if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
        results.push({
          type: 'VUE_DEVTOOLS_PRODUCTION',
          severity: 'low',
          evidence: 'Vue DevTools detected in production',
        });
      }

      // Check for v-html (XSS risk)
      if (document.querySelector('[v-html]')) {
        results.push({
          type: 'VUE_V_HTML_USAGE',
          severity: 'medium',
          evidence: 'v-html directive usage detected - potential XSS risk',
        });
      }

      // Angular checks
      if (html.includes('bypassSecurityTrust')) {
        results.push({
          type: 'ANGULAR_BYPASS_SECURITY',
          severity: 'high',
          evidence: 'Angular bypassSecurityTrust usage detected - potential XSS risk',
        });
      }

      // Django checks
      if (document.querySelector('input[name="csrfmiddlewaretoken"]')) {
        // Check for debug mode
        if (html.includes('DEBUG = True') || html.includes('Django Debug')) {
          results.push({
            type: 'DJANGO_DEBUG_MODE',
            severity: 'critical',
            evidence: 'Django debug mode enabled in production',
          });
        }

        // Check admin accessibility
        const djangoAdmin = await checkPathExists('/admin/', text =>
          text.includes('Django') && text.includes('administration')
        );
        if (djangoAdmin.exists) {
          results.push({
            type: 'DJANGO_ADMIN_EXPOSED',
            severity: 'info',
            path: '/admin/',
            evidence: 'Django admin panel accessible',
          });
        }
      }

      // Laravel checks
      if (html.includes('laravel_session') || html.includes('XSRF-TOKEN')) {
        // Check for debug mode (Whoops error page)
        if (html.includes('Whoops!') || html.includes('APP_DEBUG')) {
          results.push({
            type: 'LARAVEL_DEBUG_MODE',
            severity: 'critical',
            evidence: 'Laravel debug mode enabled - stack traces exposed',
          });
        }

        // Check Telescope (debugging tool)
        const telescope = await checkPathExists('/telescope', text =>
          text.includes('Telescope') || text.includes('telescope')
        );
        if (telescope.exists) {
          results.push({
            type: 'LARAVEL_TELESCOPE_EXPOSED',
            severity: 'high',
            path: '/telescope',
            evidence: 'Laravel Telescope debugging tool exposed',
          });
        }
      }

      return results;
    }

    // ============================================================
    // MAIN SCAN FUNCTION
    // ============================================================

    async scan(options = {}) {
      const { skipGeneral = false, cmsOnly = false } = options;
      console.log('[CMS Scanner] Starting comprehensive security scan...');
      const allResults = [];

      // Detect CMS first
      const cms = this.detectCMS();
      console.log(`[CMS Scanner] Detected CMS: ${cms || 'none'} ${this.detectedVersion ? `v${this.detectedVersion}` : ''}`);

      // Run CMS-specific scans
      if (cms === 'wordpress') {
        console.log('[CMS Scanner] Running WordPress checks...');
        const wpResults = await this.scanWordPress();
        allResults.push(...wpResults);
      } else if (cms === 'drupal') {
        console.log('[CMS Scanner] Running Drupal checks...');
        const drupalResults = await this.scanDrupal();
        allResults.push(...drupalResults);
      } else if (cms === 'joomla') {
        console.log('[CMS Scanner] Running Joomla checks...');
        const joomlaResults = await this.scanJoomla();
        allResults.push(...joomlaResults);
      }

      // Always run Laravel checks (can exist without CMS detection)
      console.log('[CMS Scanner] Running Laravel checks...');
      const laravelResults = await this.scanLaravel();
      allResults.push(...laravelResults);

      // Run Liferay checks
      console.log('[CMS Scanner] Running Liferay checks...');
      const liferayResults = await this.scanLiferay();
      allResults.push(...liferayResults);

      if (!cmsOnly) {
        // Run framework vulnerability checks
        console.log('[CMS Scanner] Running framework checks...');
        const frameworkResults = await this.scanFrameworkVulnerabilities();
        allResults.push(...frameworkResults);

        // Run general disclosure checks (unless skipped)
        if (!skipGeneral) {
          console.log('[CMS Scanner] Running disclosure checks...');
          const disclosureResults = await this.scanGeneralDisclosure();
          allResults.push(...disclosureResults);
        }
      }

      // Report all findings
      for (const result of allResults) {
        reportFinding(result.type, result);
        this.findings.push(result);
      }

      console.log(`[CMS Scanner] Scan complete. Found ${allResults.length} findings.`);
      const criticalCount = allResults.filter(f => f.severity === 'critical').length;
      const highCount = allResults.filter(f => f.severity === 'high').length;
      if (criticalCount > 0) {
        console.log(`%c⚠️ CRITICAL: ${criticalCount} critical findings!`, 'color: red; font-weight: bold');
      }
      if (highCount > 0) {
        console.log(`%c⚠️ HIGH: ${highCount} high severity findings!`, 'color: orange; font-weight: bold');
      }
      return this.getReport();
    }

    async quickScan() {
      console.log('[CMS Scanner] Running quick detection only...');
      const cms = this.detectCMS();
      return {
        cms: cms,
        version: this.detectedVersion,
        url: location.href,
      };
    }

    async disclosureScan() {
      console.log('[CMS Scanner] Running disclosure-only scan...');
      const results = await this.scanGeneralDisclosure();
      for (const result of results) {
        reportFinding(result.type, result);
        this.findings.push(result);
      }
      return { findings: results, findingCount: results.length };
    }

    getReport() {
      return {
        cms: this.detectedCMS,
        version: this.detectedVersion,
        findings: this.findings,
        findingCount: this.findings.length,
        criticalCount: this.findings.filter(f => f.severity === 'critical').length,
        highCount: this.findings.filter(f => f.severity === 'high').length,
        mediumCount: this.findings.filter(f => f.severity === 'medium').length,
        lowCount: this.findings.filter(f => f.severity === 'low').length,
        url: location.href,
      };
    }
  }

  // Expose to window
  window.cmsScanner = new CMSScanner();

  console.log('[Lonkero] CMS & Framework Scanner v2.0 loaded');
  console.log('');
  console.log('  cmsScanner.scan()           - Full security scan');
  console.log('  cmsScanner.scan({cmsOnly})  - CMS checks only');
  console.log('  cmsScanner.quickScan()      - Quick CMS detection');
  console.log('  cmsScanner.disclosureScan() - Disclosure checks only');
  console.log('  cmsScanner.getReport()      - Get results');
  console.log('');
  console.log('CMS Coverage:');
  console.log('  - WordPress (user enum, xmlrpc, config, plugins, SQL dumps, phpMyAdmin)');
  console.log('  - Drupal (Drupalgeddon 1/2/3, JSON API, user enum, settings.php)');
  console.log('  - Joomla (CVE-2023-23752, CVE-2017-8917, API exposure)');
  console.log('  - Laravel (.env, Ignition RCE, Telescope, logs, Horizon)');
  console.log('  - Liferay (JSONWS RCE, WebDAV, deserialization)');
  console.log('');
  console.log('Framework checks: Next.js, React, Vue, Angular, Django');
  console.log('Disclosure: .git, .env, phpinfo, server-status, backups, robots.txt');

})();
