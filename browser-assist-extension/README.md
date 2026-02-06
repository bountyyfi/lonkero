# Lonkero Security Scanner - Browser Extension

Advanced browser-based security scanning with real-time vulnerability detection.

## Features

### Vulnerable JavaScript Library Detection (Merlin Scanner)

Automatically detects vulnerable JavaScript libraries on any page with CVE mapping:

- **50+ libraries supported**: jQuery, Bootstrap, Angular, Vue, React, Lodash, Moment.js, Axios, Handlebars, DOMPurify, Next.js, TinyMCE, CKEditor, and many more
- **CVE database**: Each vulnerability links to specific CVEs with severity ratings
- **Version detection**: Extracts versions from global objects, script URLs, and library metadata
- **Real-time scanning**: Runs automatically on page load

Example findings:
```
jQuery 2.2.4 - CVE-2020-11022, CVE-2020-11023 (Medium)
  XSS when passing HTML to DOM manipulation methods

Bootstrap 3.3.7 - CVE-2019-8331, CVE-2018-14041 (Medium)
  XSS in data-template, data-content and data-title attributes
```

### Active XSS Scanner (v2.0)

Comprehensive XSS detection ported from Lonkero CLI Rust scanners:

**Three Detection Layers:**
1. **Proof-Based Detection**: Canary injection → context analysis → escape testing → exploitability proof
2. **DOM Differential Analysis**: Compares page DOM before/after payload to detect injected elements
3. **Static Taint Analysis**: Traces data from sources (location.hash, search) to sinks (innerHTML, eval)

**17 Reflection Contexts:**
- HTML body, comments
- Attributes (double-quoted, single-quoted, unquoted, data-*)
- JavaScript (string double/single, template literals, direct code)
- Event handlers (onclick, onerror, etc.)
- JavaScript URLs (href="javascript:")
- CSS (style tags, inline styles)
- Script src attributes

**Smart Features:**
- Auto-scans pages with URL parameters
- Discovers hidden reflectable parameters (probes common names like q, search, id, msg)
- 40+ payloads including WAF evasion techniques
- Mathematical proof of exploitability (not just pattern matching)

### Technology Detection

Wappalyzer-style fingerprinting identifies:

**CMS Platforms**
- WordPress, Drupal, Joomla, Shopify, Magento, Ghost, Squarespace, Wix, Webflow

**JavaScript Frameworks**
- Next.js, Nuxt.js, Gatsby, React, Vue, Angular, Svelte, Remix, Astro

**Cloud Providers**
- AWS (S3, CloudFront, ELB), Azure, Google Cloud, Cloudflare, Fastly, Vercel, Netlify

**Analytics & Marketing**
- Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Segment, Mixpanel

**CSS Frameworks**
- Tailwind CSS, Bootstrap, Material UI, Chakra UI, Bulma

**Build Tools**
- Webpack, Vite, Parcel, Turbopack

### Form Fuzzer (Smart v2.0)

Intelligent form testing with adaptive behavior:

**Smart Probing** (v3.5.2):
- Detects working HTTP method (tries POST → GET → PUT → PATCH)
- Early abort after 3 consecutive errors (no wasted requests)
- Baseline response comparison for anomaly detection
- Server fingerprinting from error pages

**SPA Support**:
- Detects React/Vue/Angular virtual forms
- Recognizes forms without traditional `<form>` tags
- Framework-specific attribute detection

**Payloads**:
- Context-aware: login fields get SQLi, search gets XSS
- Focused payload sets (6 per field vs generic 8+)
- XSS, SQLi, SSTI, Command Injection, Path Traversal

### GraphQL Fuzzer

Smart GraphQL security testing with source code analysis:

**Source Code Extraction** (v3.5.1):
- Extracts `gql\`...\`` tagged template literals (Apollo, urql)
- Parses `{ query: "..." }` objects from JS
- Finds queries in `__NEXT_DATA__` and JSON embeds
- Discovers Apollo persisted query hashes
- Uses REAL app queries for targeted fuzzing

**Schema-Based Testing**:
- Introspection query detection
- Full schema extraction and analysis
- IDOR testing on user/account/order queries
- Dangerous mutation discovery

**Advanced Attacks** (ported from Rust scanner):
- Batch query attacks (mutation batching, alias coalescing)
- Query complexity DoS (deep nesting, circular refs)
- Persisted query attacks (APQ probing, hash guessing)
- Fragment attacks (spreading, recursive)
- Directive abuse (custom directives, flooding)
- Authorization bypass testing
- Time-based SQL injection

### Request Interceptor

Capture and modify HTTP traffic:
- View request/response pairs
- Edit and replay requests
- Export to curl/fetch formats

## Installation

1. Open Chrome/Edge and navigate to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `browser-assist-extension` folder

## Usage

Click the Lonkero icon in your browser toolbar to open the popup:

- **Findings tab**: View all detected vulnerabilities
- **Forms tab**: See detected forms and run form fuzzing
- **Requests tab**: View intercepted requests, edit and replay
- **Settings tab**: Configure scanning options

### Manual Scanning

Open browser console and use:

```javascript
// Run XSS scan on current page
xssScanner.scan()

// Run Merlin library scan
merlin.scan()

// Test specific parameter for XSS
xssScanner.testParameter(location.href, 'search', 'test')

// GraphQL Fuzzer - extracts queries from source & fuzzes
gqlFuzz.fuzz()                      // Auto-discover and full scan
gqlFuzz.fuzz('/graphql')            // Scan specific endpoint
gqlFuzz.extractQueriesFromSource()  // Just extract queries (no fuzzing)
gqlFuzz.quickFuzz()                 // Basic tests only
gqlFuzz.aggressiveFuzz()            // Full scan + DoS tests
gqlFuzz.getReport()                 // Get detailed results

// Smart Form Fuzzer v2.0
formFuzzer.discoverAndFuzzForms()   // Full smart fuzzing
formFuzzer.quickScan()              // Just probe forms (no payloads)
formFuzzer.getReport()              // Get results

// CMS & Framework Scanner (WordPress, Drupal, Joomla)
cmsScanner.scan()                   // Full security scan
cmsScanner.quickScan()              // Quick CMS detection only
cmsScanner.getReport()              // Get results
```

## Architecture

```
popup.html/js     - Extension popup UI
content.js        - Content script (bridge between page and extension)
background.js     - Service worker for request interception
merlin.js         - Vulnerable library scanner (injected into page)
xss-scanner.js    - Active XSS scanner (injected into page)
formfuzzer.js     - Form fuzzing engine
graphql-fuzzer.js - GraphQL testing
cms-scanner.js    - CMS/Framework vulnerability scanner (WP, Drupal, Joomla)
interceptors.js   - Request/response capture
```

## Version History

### v3.6.0
- **XSS Scanner v2.0** - Complete rewrite ported from Rust scanners:
  - **Proof-Based Detection**: Injects canary, analyzes reflection context, tests escaping behavior, mathematically proves exploitability
  - **DOM Differential Analysis**: Compares DOM structure before/after payload injection to detect new scripts, event handlers, javascript: URLs
  - **Static Taint Analysis**: Traces data flow from sources (location.hash, search, referrer) to sinks (innerHTML, eval, document.write)
  - **17 Reflection Contexts**: HTML body, JS strings, attributes, event handlers, template literals, CSS, comments, etc.
  - **Auto-Discovery**: Probes common parameter names (q, search, id, msg, etc.) for reflection points
  - **40+ XSS Payloads**: Priority payloads + evasion techniques (case variation, encoding, tag nesting, alternative handlers)
  - **Auto-Scan**: Automatically scans pages with URL parameters or hash
- Console API:
  - `xssScanner.scan()` - Full comprehensive scan (all phases)
  - `xssScanner.quickScan()` - Fast scan (DOM XSS + existing params)
  - `xssScanner.testParameter(url, param, value)` - Test single parameter
  - `xssScanner.diffFuzz(url, param)` - Differential fuzzing
  - `xssScanner.analyzeDOM()` - DOM XSS taint analysis only

### v3.5.4
- **CMS & Framework Security Scanner** - Ported from Rust scanner:
  - WordPress: user enumeration, REST API exposure, XML-RPC, config/debug logs, plugin vulnerabilities
  - Drupal: Drupalgeddon/Drupalgeddon2 CVE checks, JSON API, user enumeration, version disclosure
  - Joomla: CVE-2023-23752, API exposure, configuration backup files
  - Framework checks: Next.js sensitive data, React/Vue devtools, Django/Laravel debug mode
- **Fixed "Extension context invalidated" errors** - Graceful handling when extension reloads
  - Safe message sending with automatic retry for pending findings
  - No more console errors during long fuzzing sessions
- Added `cmsScanner.scan()` and `cmsScanner.quickScan()` console API

### v3.5.3
- **UI Framework Form Detection** - Detects forms in modern Vue/React UI libraries:
  - Quasar Framework (q-field, q-input, q-btn)
  - Vuetify (v-form, v-text-field, v-input, v-btn)
  - Element UI / Element Plus (el-form, el-input, el-button)
  - Ant Design Vue (ant-form, ant-input, ant-btn)
  - PrimeVue (p-inputtext, p-field, p-button)
  - Chakra UI form components
- Improved input name detection using aria-label and associated labels
- Better virtual form discovery for SPA frameworks

### v3.5.2
- **Smart Form Fuzzer v2.0** - Complete rewrite with intelligent behavior:
  - Probes forms to detect working HTTP method (POST/GET/PUT/PATCH)
  - Early abort after 3 consecutive 4xx errors (no more 76 useless requests)
  - SPA form detection (React/Vue/Angular virtual forms)
  - Baseline response comparison to detect interesting changes
  - Server fingerprinting from first error response
  - Reduced payload counts (6 vs 8) focused on high-impact vulnerabilities

### v3.5.1
- **GraphQL: Source Code Query Extraction** - Extracts real queries from page JS (gql tags, query objects, __NEXT_DATA__)
- **GraphQL: Smarter Fuzzing** - Uses extracted queries for targeted SQLi/NoSQLi/XSS/IDOR testing
- **Form Fuzzer: Server Fingerprinting** - Extracts server info from error pages (OpenResty, nginx, etc.)
- Server fingerprinting now works on 405/error responses instead of stopping

### v3.5.0
- Added Security Headers Analysis (CSP, CORS, HSTS, X-Frame-Options, X-Content-Type-Options)
- Added Cookie Security Audit (HttpOnly, Secure, SameSite)
- Added Open Redirect Detection (redirect, url, next params)
- Added JWT Decoder & Analysis (alg:none, expired, no-expiry, sensitive data)
- Added Source Map Detection (.map files)
- Added Sensitive Paths Check (/.git, /.env, /admin, etc.)
- Added Mixed Content Detection (HTTP on HTTPS)
- Full API key display (no truncation)
- Improved deduplication for new finding types

### v3.4.0
- Fixed technology detection (case-sensitive pattern matching bug)
- Added clickable findings with detail view
- Added technologies display in overview tab
- Improved severity classification for findings

### v3.3.0
- Added Merlin.js vulnerable library scanner with 50+ libraries and CVE database
- Added proof-based XSS scanner with context analysis
- Added technology detection (CMS, frameworks, cloud, analytics)
- Enlarged popup for better request editing and response viewing

### v3.2.0
- Added GraphQL fuzzer
- Request interception improvements

### v3.1.0
- Added form fuzzer
- Initial release

## Integration with Lonkero CLI

This extension works standalone or integrates with the Lonkero CLI tool for:
- Exporting findings to CLI format
- Importing CLI scan results
- Coordinated scanning workflows

## License

Part of the Lonkero security toolkit.
