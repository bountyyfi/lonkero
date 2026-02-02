// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Merlin - Vulnerable JavaScript Library Scanner
 * Browser extension version - detects vulnerable third-party JS libraries
 */

(function() {
  'use strict';

  if (window.__merlinInjected) return;
  window.__merlinInjected = true;

  // Vulnerability database - CVE data for JS libraries
  const VULN_DATABASE = {
    'jquery': [
      { from: null, to: '1.6.3', cves: ['CVE-2011-4969'], severity: 'medium', desc: 'XSS vulnerability in jQuery before 1.6.3' },
      { from: null, to: '1.9.0', cves: ['CVE-2012-6708'], severity: 'medium', desc: 'Selector-interpreted XSS vulnerability' },
      { from: '1.4.0', to: '3.0.0', cves: ['CVE-2015-9251'], severity: 'medium', desc: 'Cross-site scripting vulnerability' },
      { from: '1.1.4', to: '3.4.0', cves: ['CVE-2019-11358'], severity: 'medium', desc: 'Prototype pollution via object extend' },
      { from: '1.0.3', to: '3.5.0', cves: ['CVE-2020-11022', 'CVE-2020-11023'], severity: 'medium', desc: 'XSS when passing HTML to DOM manipulation methods' },
    ],
    'jquery-ui': [
      { from: '1.7.0', to: '1.10.0', cves: ['CVE-2010-5312'], severity: 'medium', desc: 'XSS in dialog closeText' },
      { from: null, to: '1.12.0', cves: ['CVE-2016-7103'], severity: 'medium', desc: 'XSS vulnerability in dialog function' },
      { from: null, to: '1.13.0', cves: ['CVE-2021-41182', 'CVE-2021-41183', 'CVE-2021-41184'], severity: 'medium', desc: 'Multiple XSS vulnerabilities' },
      { from: null, to: '1.13.2', cves: ['CVE-2022-31160'], severity: 'medium', desc: 'XSS in checkboxradio widget' },
    ],
    'angularjs': [
      { from: null, to: '1.5.0-beta.1', cves: ['CVE-2020-7676'], severity: 'medium', desc: 'XSS vulnerability' },
      { from: null, to: '1.6.0', cves: [], severity: 'high', desc: 'Sandbox escape vulnerability' },
      { from: '1.5.0', to: '1.6.9', cves: [], severity: 'high', desc: 'ngSanitize bypass vulnerability' },
      { from: null, to: '1.8.0', cves: ['CVE-2020-7676'], severity: 'medium', desc: 'Prototype pollution vulnerability' },
      { from: '1.3.0', to: '1.8.4', cves: ['CVE-2024-21490'], severity: 'high', desc: 'ReDoS vulnerability in ng-srcset' },
      { from: '0', to: '1.8.4', cves: ['CVE-2024-8373'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'bootstrap': [
      { from: null, to: '3.4.0', cves: ['CVE-2018-20676', 'CVE-2018-20677'], severity: 'medium', desc: 'XSS in tooltip/popover' },
      { from: '1.4.0', to: '3.4.1', cves: ['CVE-2024-6485'], severity: 'medium', desc: 'XSS in carousel component' },
      { from: '4.0.0', to: '4.3.1', cves: ['CVE-2019-8331'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'lodash': [
      { from: null, to: '4.17.5', cves: ['CVE-2018-3721'], severity: 'medium', desc: 'Prototype pollution' },
      { from: null, to: '4.17.11', cves: ['CVE-2018-16487'], severity: 'high', desc: 'Prototype pollution via merge/mergeWith/defaultsDeep' },
      { from: null, to: '4.17.12', cves: ['CVE-2019-10744'], severity: 'critical', desc: 'Prototype pollution in defaultsDeep' },
      { from: '3.7.0', to: '4.17.19', cves: ['CVE-2020-8203'], severity: 'high', desc: 'Prototype pollution via zipObjectDeep' },
      { from: null, to: '4.17.21', cves: ['CVE-2021-23337'], severity: 'high', desc: 'Command injection via template function' },
    ],
    'moment': [
      { from: null, to: '2.11.2', cves: [], severity: 'low', desc: 'ReDoS vulnerability' },
      { from: null, to: '2.19.3', cves: ['CVE-2017-18214'], severity: 'high', desc: 'ReDoS via crafted date string' },
      { from: null, to: '2.29.2', cves: ['CVE-2022-24785'], severity: 'high', desc: 'Path traversal vulnerability' },
      { from: '2.18.0', to: '2.29.4', cves: ['CVE-2022-31129'], severity: 'high', desc: 'ReDoS via RFC 2822 date parsing' },
    ],
    'axios': [
      { from: null, to: '0.18.1', cves: ['CVE-2019-10742'], severity: 'high', desc: 'Server-side request forgery' },
      { from: null, to: '0.21.1', cves: ['CVE-2020-28168'], severity: 'medium', desc: 'SSRF via follow redirect' },
      { from: null, to: '0.21.2', cves: ['CVE-2021-3749'], severity: 'high', desc: 'ReDoS vulnerability' },
      { from: '0.8.1', to: '1.6.0', cves: ['CVE-2023-45857'], severity: 'medium', desc: 'XSRF token exposure via CORS' },
      { from: '1.3.2', to: '1.7.4', cves: ['CVE-2024-39338'], severity: 'high', desc: 'SSRF vulnerability' },
    ],
    'vue': [
      { from: null, to: '2.5.17', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
      { from: '2.0.0', to: '2.7.17', cves: ['CVE-2024-9506'], severity: 'medium', desc: 'ReDoS in parseHTML function' },
    ],
    'react': [
      { from: '0.0.1', to: '0.14.0', cves: [], severity: 'high', desc: 'XSS via spoofed React element' },
      { from: '16.0.0', to: '16.4.2', cves: ['CVE-2018-6341'], severity: 'medium', desc: 'XSS in server-side rendering' },
    ],
    'handlebars': [
      { from: null, to: '4.0.14', cves: ['CVE-2019-19919'], severity: 'critical', desc: 'Prototype pollution via lookup helper' },
      { from: '4.0.0', to: '4.5.3', cves: ['CVE-2019-20920'], severity: 'critical', desc: 'Arbitrary code execution via lookup helper' },
      { from: null, to: '4.7.7', cves: ['CVE-2021-23369', 'CVE-2021-23383'], severity: 'critical', desc: 'Remote code execution vulnerability' },
    ],
    'dompurify': [
      { from: '0', to: '2.4.2', cves: ['CVE-2024-48910'], severity: 'high', desc: 'Mutation XSS vulnerability' },
      { from: '0', to: '2.5.4', cves: ['CVE-2024-45801'], severity: 'high', desc: 'XSS bypass via nesting' },
      { from: '0', to: '3.2.4', cves: ['CVE-2025-26791'], severity: 'high', desc: 'XSS bypass vulnerability' },
    ],
    'next': [
      { from: '11.1.4', to: '14.2.25', cves: ['CVE-2025-29927'], severity: 'critical', desc: 'Middleware authorization bypass' },
      { from: '9.5.5', to: '14.2.15', cves: ['CVE-2024-51479'], severity: 'high', desc: 'Authorization bypass vulnerability' },
      { from: '13.5.1', to: '14.2.10', cves: ['CVE-2024-46982'], severity: 'high', desc: 'Cache poisoning vulnerability' },
    ],
    'tinymce': [
      { from: null, to: '5.10.9', cves: ['CVE-2023-48219'], severity: 'medium', desc: 'XSS vulnerability' },
      { from: '0', to: '6.8.4', cves: ['CVE-2024-38356', 'CVE-2024-38357'], severity: 'medium', desc: 'Multiple XSS vulnerabilities' },
    ],
    'ckeditor4': [
      { from: null, to: '4.21.0', cves: ['CVE-2023-28439'], severity: 'medium', desc: 'XSS vulnerability' },
      { from: null, to: '4.18.0', cves: ['CVE-2022-24728'], severity: 'medium', desc: 'XSS in HTML processor' },
    ],
    'underscore': [
      { from: '1.3.2', to: '1.12.1', cves: ['CVE-2021-23358'], severity: 'high', desc: 'Arbitrary code execution via template function' },
    ],
    'pdfjs': [
      { from: '0', to: '4.2.67', cves: ['CVE-2024-4367'], severity: 'critical', desc: 'Arbitrary JavaScript execution' },
    ],
    'datatables': [
      { from: null, to: '1.11.3', cves: ['CVE-2020-28458'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'select2': [
      { from: '0', to: '4.0.6', cves: ['CVE-2016-10744'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'highcharts': [
      { from: null, to: '9.0.0', cves: ['CVE-2021-29489'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'chartjs': [
      { from: null, to: '2.9.4', cves: [], severity: 'medium', desc: 'Prototype pollution' },
    ],
    'dojo': [
      { from: '1.10.0', to: '1.17.0', cves: ['CVE-2020-4051'], severity: 'critical', desc: 'Prototype pollution' },
    ],
    'knockout': [
      { from: null, to: '3.5.0', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'svelte': [
      { from: null, to: '4.2.19', cves: ['CVE-2024-45047'], severity: 'high', desc: 'XSS vulnerability' },
    ],
    'mustache': [
      { from: null, to: '2.2.1', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'prototype': [
      { from: null, to: '1.6.0.2', cves: ['CVE-2008-7220'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'backbone': [
      { from: null, to: '0.5.0', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'ember': [
      { from: null, to: '3.24.7', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
      { from: '4.0.0', to: '4.8.1', cves: [], severity: 'medium', desc: 'Security vulnerability' },
    ],
    'sweetalert': [
      { from: null, to: '1.1.3', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'sweetalert2': [
      { from: null, to: '9.10.13', cves: ['CVE-2020-15270'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'quill': [
      { from: null, to: '1.3.7', cves: ['CVE-2021-32819'], severity: 'medium', desc: 'XSS vulnerability' },
      { from: null, to: '2.0.0-dev.4', cves: ['CVE-2023-37466'], severity: 'medium', desc: 'XSS via video handler' },
    ],
    'prismjs': [
      { from: null, to: '1.25.0', cves: ['CVE-2021-3801'], severity: 'high', desc: 'ReDoS vulnerability' },
      { from: null, to: '1.27.0', cves: ['CVE-2022-23647'], severity: 'high', desc: 'XSS in command-line plugin' },
    ],
    'marked': [
      { from: null, to: '0.3.6', cves: ['CVE-2017-17461'], severity: 'high', desc: 'ReDoS vulnerability' },
      { from: null, to: '0.3.9', cves: ['CVE-2017-1000427'], severity: 'high', desc: 'XSS vulnerability' },
      { from: null, to: '4.0.10', cves: ['CVE-2022-21680', 'CVE-2022-21681'], severity: 'high', desc: 'ReDoS via crafted markdown' },
    ],
    'showdown': [
      { from: null, to: '1.9.1', cves: ['CVE-2020-26289'], severity: 'high', desc: 'ReDoS vulnerability' },
      { from: null, to: '2.1.0', cves: ['CVE-2022-24788'], severity: 'high', desc: 'XSS via crafted input' },
    ],
    'videojs': [
      { from: null, to: '7.14.3', cves: ['CVE-2021-23414'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'hlsjs': [
      { from: null, to: '0.14.17', cves: ['CVE-2021-23409'], severity: 'high', desc: 'XSS vulnerability' },
    ],
    'summernote': [
      { from: null, to: '0.8.18', cves: ['CVE-2020-10671'], severity: 'medium', desc: 'XSS vulnerability' },
      { from: null, to: '0.8.20', cves: ['CVE-2023-42805'], severity: 'medium', desc: 'XSS via code view textarea' },
    ],
    'codemirror': [
      { from: null, to: '5.58.2', cves: ['CVE-2020-7774'], severity: 'medium', desc: 'Prototype pollution' },
    ],
    'socketio': [
      { from: null, to: '2.4.0', cves: ['CVE-2020-28481'], severity: 'medium', desc: 'Unauthorized namespace access' },
    ],
    'dropzone': [
      { from: null, to: '5.5.0', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'immer': [
      { from: null, to: '9.0.6', cves: ['CVE-2021-23436'], severity: 'critical', desc: 'Prototype pollution vulnerability' },
    ],
    'ajv': [
      { from: null, to: '6.12.3', cves: ['CVE-2020-15366'], severity: 'medium', desc: 'Prototype pollution vulnerability' },
    ],
    'leaflet': [
      { from: null, to: '1.4.0', cves: [], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'xlsx': [
      { from: null, to: '0.17.0', cves: ['CVE-2021-32012'], severity: 'high', desc: 'Arbitrary file write vulnerability' },
      { from: null, to: '0.19.3', cves: ['CVE-2023-30533'], severity: 'high', desc: 'Remote code execution via crafted file' },
    ],
    'froala': [
      { from: '0', to: '4.3.1', cves: ['CVE-2024-51434'], severity: 'medium', desc: 'XSS vulnerability' },
    ],
    'mathjax': [
      { from: '0', to: '2.7.10', cves: ['CVE-2023-39663'], severity: 'high', desc: 'XSS vulnerability' },
    ],
    'highlightjs': [
      { from: null, to: '9.18.2', cves: ['CVE-2020-26237'], severity: 'medium', desc: 'Prototype pollution' },
      { from: '10.0.0', to: '10.4.1', cves: ['CVE-2020-26237'], severity: 'medium', desc: 'Prototype pollution' },
    ],
    'sanitize-html': [
      { from: null, to: '2.3.2', cves: ['CVE-2021-26539'], severity: 'medium', desc: 'XSS bypass vulnerability' },
      { from: null, to: '2.7.1', cves: ['CVE-2022-25887'], severity: 'medium', desc: 'XSS via crafted HTML' },
    ],
    'qs': [
      { from: null, to: '6.2.3', cves: ['CVE-2017-1000048'], severity: 'high', desc: 'Prototype pollution' },
      { from: null, to: '6.10.3', cves: ['CVE-2022-24999'], severity: 'high', desc: 'Prototype pollution via qs.parse' },
    ],
    'async': [
      { from: null, to: '2.6.4', cves: ['CVE-2021-43138'], severity: 'high', desc: 'Prototype pollution vulnerability' },
    ],
    'flat': [
      { from: null, to: '5.0.1', cves: ['CVE-2020-36632'], severity: 'critical', desc: 'Prototype pollution' },
    ],
    'object-path': [
      { from: null, to: '0.11.5', cves: ['CVE-2020-15256'], severity: 'critical', desc: 'Prototype pollution' },
    ],
    'dot-prop': [
      { from: null, to: '5.3.0', cves: ['CVE-2020-8116'], severity: 'high', desc: 'Prototype pollution' },
    ],
    'deep-extend': [
      { from: null, to: '0.5.1', cves: ['CVE-2018-3750'], severity: 'critical', desc: 'Prototype pollution' },
    ],
    'merge': [
      { from: null, to: '2.1.1', cves: ['CVE-2020-28499'], severity: 'critical', desc: 'Prototype pollution' },
    ],
  };

  // Version comparison utilities
  function parseVersion(version) {
    const lower = version.toLowerCase();
    const numericPart = lower.split(/[^0-9.]/)[0];
    return numericPart.split('.').map(n => parseInt(n, 10) || 0);
  }

  function compareVersions(a, b) {
    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
      const av = a[i] || 0;
      const bv = b[i] || 0;
      if (av < bv) return -1;
      if (av > bv) return 1;
    }
    return 0;
  }

  function versionInRange(version, from, to) {
    const parsedVersion = parseVersion(version);
    const parsedTo = parseVersion(to);

    // Check upper bound (strictly less than)
    if (compareVersions(parsedVersion, parsedTo) >= 0) {
      return false;
    }

    // Check lower bound if exists (greater than or equal)
    if (from) {
      const parsedFrom = parseVersion(from);
      if (compareVersions(parsedVersion, parsedFrom) < 0) {
        return false;
      }
    }

    return true;
  }

  // Check library against vulnerability database
  function checkLibrary(name, version) {
    const nameLower = name.toLowerCase();
    const vulns = VULN_DATABASE[nameLower];
    if (!vulns) return [];

    const matches = [];
    for (const vuln of vulns) {
      if (versionInRange(version, vuln.from, vuln.to)) {
        matches.push({
          library: name,
          version: version,
          cves: vuln.cves,
          severity: vuln.severity,
          description: vuln.desc,
        });
      }
    }
    return matches;
  }

  // Detection patterns for various libraries
  const detectedLibraries = new Map();

  // Detect jQuery
  function detectJQuery() {
    if (window.jQuery || window.$?.fn?.jquery) {
      const version = window.jQuery?.fn?.jquery || window.$?.fn?.jquery;
      if (version) {
        detectedLibraries.set('jquery', version);
      }
    }
  }

  // Detect Angular
  function detectAngular() {
    if (window.angular?.version?.full) {
      detectedLibraries.set('angularjs', window.angular.version.full);
    }
    // Modern Angular
    if (window.ng?.VERSION?.full) {
      detectedLibraries.set('angular', window.ng.VERSION.full);
    }
  }

  // Detect Vue
  function detectVue() {
    if (window.Vue?.version) {
      detectedLibraries.set('vue', window.Vue.version);
    }
    // Vue 3 global
    if (window.__VUE__?.version) {
      detectedLibraries.set('vue', window.__VUE__.version);
    }
  }

  // Detect React
  function detectReact() {
    if (window.React?.version) {
      detectedLibraries.set('react', window.React.version);
    }
  }

  // Detect Lodash
  function detectLodash() {
    if (window._?.VERSION) {
      detectedLibraries.set('lodash', window._.VERSION);
    }
  }

  // Detect Moment
  function detectMoment() {
    if (window.moment?.version) {
      detectedLibraries.set('moment', window.moment.version);
    }
  }

  // Detect Bootstrap
  function detectBootstrap() {
    if (window.bootstrap?.VERSION) {
      detectedLibraries.set('bootstrap', window.bootstrap.VERSION);
    }
    // jQuery-based Bootstrap
    if (window.$.fn?.tooltip?.Constructor?.VERSION) {
      detectedLibraries.set('bootstrap', window.$.fn.tooltip.Constructor.VERSION);
    }
  }

  // Detect Axios
  function detectAxios() {
    if (window.axios?.VERSION) {
      detectedLibraries.set('axios', window.axios.VERSION);
    }
  }

  // Detect Handlebars
  function detectHandlebars() {
    if (window.Handlebars?.VERSION) {
      detectedLibraries.set('handlebars', window.Handlebars.VERSION);
    }
  }

  // Detect DOMPurify
  function detectDOMPurify() {
    if (window.DOMPurify?.version) {
      detectedLibraries.set('dompurify', window.DOMPurify.version);
    }
  }

  // Detect jQuery UI
  function detectJQueryUI() {
    if (window.$.ui?.version) {
      detectedLibraries.set('jquery-ui', window.$.ui.version);
    }
  }

  // Detect TinyMCE
  function detectTinyMCE() {
    if (window.tinymce?.majorVersion && window.tinymce?.minorVersion) {
      detectedLibraries.set('tinymce', `${window.tinymce.majorVersion}.${window.tinymce.minorVersion}`);
    }
  }

  // Detect CKEditor
  function detectCKEditor() {
    if (window.CKEDITOR?.version) {
      detectedLibraries.set('ckeditor4', window.CKEDITOR.version);
    }
    if (window.ClassicEditor?.builtinPlugins) {
      // CKEditor 5 - harder to get version
      detectedLibraries.set('ckeditor5', 'detected');
    }
  }

  // Detect Knockout
  function detectKnockout() {
    if (window.ko?.version) {
      detectedLibraries.set('knockout', window.ko.version);
    }
  }

  // Detect Backbone
  function detectBackbone() {
    if (window.Backbone?.VERSION) {
      detectedLibraries.set('backbone', window.Backbone.VERSION);
    }
  }

  // Detect Ember
  function detectEmber() {
    if (window.Ember?.VERSION) {
      detectedLibraries.set('ember', window.Ember.VERSION);
    }
  }

  // Detect Svelte (harder, usually in compiled code)
  function detectSvelte() {
    // Svelte components often have specific markers
    if (document.querySelector('[class^="svelte-"]')) {
      // Can't easily get version, but mark as detected
      detectedLibraries.set('svelte', 'detected');
    }
  }

  // Detect Video.js
  function detectVideoJS() {
    if (window.videojs?.VERSION) {
      detectedLibraries.set('videojs', window.videojs.VERSION);
    }
  }

  // Detect Highcharts
  function detectHighcharts() {
    if (window.Highcharts?.version) {
      detectedLibraries.set('highcharts', window.Highcharts.version);
    }
  }

  // Detect Chart.js
  function detectChartJS() {
    if (window.Chart?.version) {
      detectedLibraries.set('chartjs', window.Chart.version);
    }
  }

  // Detect D3
  function detectD3() {
    if (window.d3?.version) {
      detectedLibraries.set('d3', window.d3.version);
    }
  }

  // Detect Socket.io
  function detectSocketIO() {
    if (window.io?.version) {
      detectedLibraries.set('socketio', window.io.version);
    }
  }

  // Detect Leaflet
  function detectLeaflet() {
    if (window.L?.version) {
      detectedLibraries.set('leaflet', window.L.version);
    }
  }

  // Detect Quill
  function detectQuill() {
    if (window.Quill?.version) {
      detectedLibraries.set('quill', window.Quill.version);
    }
  }

  // Detect CodeMirror
  function detectCodeMirror() {
    if (window.CodeMirror?.version) {
      detectedLibraries.set('codemirror', window.CodeMirror.version);
    }
  }

  // Detect Prism
  function detectPrism() {
    if (window.Prism) {
      // Prism doesn't expose version easily, check for specific features
      detectedLibraries.set('prismjs', 'detected');
    }
  }

  // Detect highlight.js
  function detectHighlightJS() {
    if (window.hljs?.versionString) {
      detectedLibraries.set('highlightjs', window.hljs.versionString);
    }
  }

  // Detect Dropzone
  function detectDropzone() {
    if (window.Dropzone?.version) {
      detectedLibraries.set('dropzone', window.Dropzone.version);
    }
  }

  // Detect SweetAlert
  function detectSweetAlert() {
    if (window.swal?.version) {
      detectedLibraries.set('sweetalert', window.swal.version);
    }
    if (window.Swal?.version) {
      detectedLibraries.set('sweetalert2', window.Swal.version);
    }
  }

  // Detect Summernote
  function detectSummernote() {
    if (window.$.fn?.summernote?.version) {
      detectedLibraries.set('summernote', window.$.fn.summernote.version);
    }
  }

  // Detect Froala
  function detectFroala() {
    if (window.FroalaEditor?.VERSION) {
      detectedLibraries.set('froala', window.FroalaEditor.VERSION);
    }
  }

  // Detect MathJax
  function detectMathJax() {
    if (window.MathJax?.version) {
      detectedLibraries.set('mathjax', window.MathJax.version);
    }
  }

  // Scan scripts for version strings
  function scanScriptsForVersions() {
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      const src = script.src.toLowerCase();

      // jQuery from CDN
      let match = src.match(/jquery[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('jquery')) {
        detectedLibraries.set('jquery', match[1]);
      }

      // Bootstrap from CDN
      match = src.match(/bootstrap[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('bootstrap')) {
        detectedLibraries.set('bootstrap', match[1]);
      }

      // Vue from CDN
      match = src.match(/vue[@\/](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('vue')) {
        detectedLibraries.set('vue', match[1]);
      }

      // React from CDN
      match = src.match(/react[@\/.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('react')) {
        detectedLibraries.set('react', match[1]);
      }

      // Angular from CDN
      match = src.match(/angular[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('angularjs')) {
        detectedLibraries.set('angularjs', match[1]);
      }

      // Lodash from CDN
      match = src.match(/lodash[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('lodash')) {
        detectedLibraries.set('lodash', match[1]);
      }

      // Moment from CDN
      match = src.match(/moment[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('moment')) {
        detectedLibraries.set('moment', match[1]);
      }

      // Axios from CDN
      match = src.match(/axios[.-](\d+\.\d+(?:\.\d+)?)/i);
      if (match && !detectedLibraries.has('axios')) {
        detectedLibraries.set('axios', match[1]);
      }
    });
  }

  // Report finding to content script
  function reportVulnerableLibrary(vuln) {
    window.postMessage({
      type: '__lonkero_merlin_finding__',
      finding: {
        type: 'VULNERABLE_LIBRARY',
        library: vuln.library,
        version: vuln.version,
        cves: vuln.cves,
        severity: vuln.severity,
        description: vuln.description,
        url: location.href,
      }
    }, '*');

    console.log(`[Merlin] Vulnerable library: ${vuln.library} v${vuln.version} - ${vuln.description}`);
  }

  // Main scan function
  function scan() {
    console.log('[Merlin] Starting vulnerability scan...');

    // Run all detectors
    const detectors = [
      detectJQuery,
      detectAngular,
      detectVue,
      detectReact,
      detectLodash,
      detectMoment,
      detectBootstrap,
      detectAxios,
      detectHandlebars,
      detectDOMPurify,
      detectJQueryUI,
      detectTinyMCE,
      detectCKEditor,
      detectKnockout,
      detectBackbone,
      detectEmber,
      detectSvelte,
      detectVideoJS,
      detectHighcharts,
      detectChartJS,
      detectD3,
      detectSocketIO,
      detectLeaflet,
      detectQuill,
      detectCodeMirror,
      detectPrism,
      detectHighlightJS,
      detectDropzone,
      detectSweetAlert,
      detectSummernote,
      detectFroala,
      detectMathJax,
    ];

    for (const detector of detectors) {
      try {
        detector();
      } catch (e) {
        // Ignore detection errors
      }
    }

    // Scan script tags for CDN versions
    scanScriptsForVersions();

    // Check detected libraries against vulnerability database
    let vulnCount = 0;
    for (const [name, version] of detectedLibraries) {
      if (version === 'detected') continue; // Skip libraries without version

      const vulns = checkLibrary(name, version);
      for (const vuln of vulns) {
        reportVulnerableLibrary(vuln);
        vulnCount++;
      }
    }

    // Report detected libraries (even non-vulnerable ones for visibility)
    window.postMessage({
      type: '__lonkero_merlin_scan_complete__',
      libraries: Array.from(detectedLibraries.entries()).map(([name, version]) => ({
        name,
        version,
        hasVulns: checkLibrary(name, version).length > 0,
      })),
      vulnCount,
    }, '*');

    console.log(`[Merlin] Scan complete. Found ${detectedLibraries.size} libraries, ${vulnCount} vulnerabilities.`);
  }

  // Run scan after page loads
  if (document.readyState === 'complete') {
    setTimeout(scan, 1000);
  } else {
    window.addEventListener('load', () => setTimeout(scan, 1000));
  }

  // Also run on demand via message
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data?.type === '__lonkero_run_merlin__') {
      scan();
    }
  });

  console.log('[Merlin] Vulnerable library scanner loaded');
})();
