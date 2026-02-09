<div align="center">

<img src="https://cdn.bountyy.fi/lonkero%20logo-1-Photoroom.png" alt="Lonkero Logo" width="300"/>
<br/><br/><br/>
<img src="https://cdn.bountyy.fi/lonkero_extensio.png" alt="Lonkero EXTENSIO" width="700"/>

### Browser Extension — Real-Time Security Scanning

Companion Chrome/Edge extension for the Lonkero security scanner. Works standalone or paired with the CLI.

[![Chrome](https://img.shields.io/badge/chrome-Manifest_V3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](../LICENSE)
[![Version](https://img.shields.io/badge/version-3.6.0-green.svg)](https://github.com/bountyyfi/lonkero)

**9 Scanners** | **Real-Time Detection** | **CLI Integration** | **License-Gated** | **Hardened**

**[Main Project](../README.md)** | [Features](#features) · [Security](#security-hardening) · [Installation](#installation) · [Usage](#usage) · [CLI Integration](#cli-integration-parasite-mode) · [Architecture](#architecture)

---

</div>

## Features

```
┌─────────────────────────────────────────────────────────────────┐
│  Merlin Scanner — Vulnerable JavaScript Library Detection        │
│  • 50+ libraries with CVE mapping (jQuery, Angular, Vue, etc.)  │
│  • Real-time version detection and vulnerability matching       │
│  • Severity ratings (Critical/High/Medium/Low)                  │
├─────────────────────────────────────────────────────────────────┤
│  Active XSS Scanner — Proof-Based Detection                      │
│  • Canary injection to find reflection points                   │
│  • Context analysis (HTML, JS strings, attributes, handlers)    │
│  • Escaping behavior analysis for exploitability proof          │
├─────────────────────────────────────────────────────────────────┤
│  SQL Injection Scanner — Manual-Trigger Detection                │
│  • Time-based, error-based, boolean-based techniques            │
│  • 6 DBMS fingerprints (MySQL, PostgreSQL, MSSQL, Oracle,       │
│    SQLite, MariaDB)                                             │
│  • Deep scan mode with configurable depth/page limits           │
├─────────────────────────────────────────────────────────────────┤
│  Security Headers & Misconfig Analysis (A-F Grading)              │
│  • CSP Analysis with CDN bypass detection (jsdelivr, unpkg,     │
│    cdnjs, raw.githubusercontent.com + 10 more bypass domains)   │
│  • Directive-by-directive CSP parsing (unsafe-inline, unsafe-   │
│    eval, data: URI, wildcard, missing object-src/base-uri)      │
│  • CORS Misconfiguration (Access-Control-Allow-Origin: *)       │
│  • Security header scoring: 8 categories, 100-point scale       │
│    (CSP 30, HSTS 20, X-CTO 10, Clickjack 10, Referrer 10,     │
│    Permissions 10, COOP 5, CORP 5) → A+ through F grade        │
│  • Info-leak headers (X-Debug-Token, X-Backend-Server,          │
│    X-ChromeLogger-Data, Server version disclosure)              │
├─────────────────────────────────────────────────────────────────┤
│  Cookie Security Audit                                           │
│  • Full attribute analysis via chrome.cookies API               │
│  • SameSite, Secure, HttpOnly, Domain scope validation          │
│  • __Host- and __Secure- prefix compliance checking             │
│  • JWT detection in cookie values                                │
├─────────────────────────────────────────────────────────────────┤
│  JWT Decoder & Analyzer                                          │
│  • Auto-scan localStorage/sessionStorage for JWTs               │
│  • Algorithm analysis (alg:none, weak HMAC)                     │
│  • Expiration checking, sensitive field detection                │
├─────────────────────────────────────────────────────────────────┤
│  Technology Detection — Wappalyzer-Style Fingerprinting          │
│  • CMS: WordPress, Drupal, Shopify, Magento, Ghost              │
│  • Frameworks: Next.js, Nuxt.js, React, Vue, Angular, Svelte    │
│  • Cloud: AWS, Azure, GCP, Cloudflare, Vercel, Netlify          │
│  • Analytics: Google Analytics, GTM, Hotjar, Segment            │
├─────────────────────────────────────────────────────────────────┤
│  postMessage Enumeration                                         │
│  • Hooks addEventListener('message') on all windows             │
│  • Detects listeners WITHOUT origin validation (XSS vector)     │
│  • Logs outgoing postMessage calls and target origins            │
│  • Flags wildcard (*) targetOrigin as data exposure risk         │
├─────────────────────────────────────────────────────────────────┤
│  Suspicious Comments Scanner                                     │
│  • Scans HTML comments and inline JS comments                   │
│  • 18 keywords: TODO, FIXME, HACK, BUG, XXX, password,         │
│    credential, secret, api_key, token, debug, admin, root,      │
│    hardcoded, temporary, workaround, insecure, vulnerability    │
│  • Filters GTM/analytics/IE conditional comments                │
├─────────────────────────────────────────────────────────────────┤
│  Additional Tools                                                │
│  • Form Fuzzer — Context-aware payload injection                │
│  • GraphQL Fuzzer — Introspection and schema testing            │
│  • Request Interceptor — Capture, edit, and replay requests     │
│  • CMS Scanner — WordPress, Drupal, Joomla vulnerability checks │
│  • Source Map Detection — Exposed .map files                    │
│  • Sensitive Paths — /.git, /.env, /admin discovery             │
│  • Mixed Content Detection — HTTP on HTTPS                      │
│  • Open Redirect Detection — URL parameter analysis             │
│  • Dynamic Script Scanning — MutationObserver catches lazy-     │
│    loaded chunks (Next.js, Nuxt, SPA code splitting)            │
│  • View Source / View Response — Raw and rendered HTML viewer    │
│  • Secret Detection — Mapbox, reCAPTCHA, AWS, GCP, Stripe,     │
│    Slack, GitHub tokens + Finnish HETU, Y-tunnus, IBAN, CC      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Hardening

The extension has undergone multiple rounds of security review and hardening. All scanner code runs in MAIN world (page context) with the following protections:

### License Validation

| Layer | Protection |
|-------|-----------|
| **Server-side validation** | All license checks go through `POST /validate` on the license server — no client-only bypass |
| **CLI license verified** | When CLI connects via WebSocket, the extension server-validates the license key (never trusts `licenseType` claims) |
| **Offline fallback** | Defaults to `Personal` tier with basic features only |
| **Masked input** | License key field uses `type="password"` to prevent shoulder-surfing |

### WebSocket Authentication (Parasite Mode)

| Layer | Protection |
|-------|-----------|
| **HMAC-SHA256 challenge-response** | CLI proves identity by signing a random nonce with the license key as shared secret |
| **Per-session nonce** | Fresh random challenge generated for each WebSocket connection |
| **Message size limits** | 4 MB max message, 2 MB max frame to prevent memory exhaustion |
| **Fallback pairing** | Challenge-echo only accepted for first-time pairing (when extension has no stored key) |

### Scanner Isolation & Integrity

| Layer | Protection |
|-------|-----------|
| **Symbol-based guards** | Scanner dedup guards use `Symbol.for()` keyed to per-session nonce — pages cannot pre-set them |
| **Non-enumerable globals** | Scanner APIs (`xssScanner`, `merlin`, etc.) defined with `enumerable: false` |
| **Per-session message channels** | Each content script ↔ scanner pair uses a random channel ID (`_ch`) and nonce (`_n`) |
| **Scan trigger validation** | Incoming scan triggers must include valid `_ch` + `_n` — prevents page-initiated scans |
| **Deep scan clamping** | `maxDepth` capped at 5, `maxPages` capped at 200 regardless of trigger input |

### DOM & Data Protection

| Layer | Protection |
|-------|-----------|
| **DOM hooks (MAIN world)** | `innerHTML`, `eval`, `document.write`, `addEventListener('message')`, `postMessage` monitored via `Object.defineProperty` with `configurable: false` |
| **Finding field whitelist** | Findings from scanners are extracted with explicit field names + truncation — no `...spread` from untrusted data |
| **DOM element cleanup** | License key delivery element (`#__lk_c`) removed after 2 seconds |
| **Per-install signing key** | Timestamps signed with a random 256-bit key stored in `chrome.storage.local` (not the public `chrome.runtime.id`) |

### Network Security

| Layer | Protection |
|-------|-----------|
| **SSRF deny list** | Private IPs (RFC 1918), loopback, link-local, cloud metadata (`169.254.169.254`, `metadata.google.internal`) blocked regardless of CLI scope |
| **Replay gated** | `replayRequest` requires active license before execution |
| **No external JS** | All code is bundled — no CDN or remote script loading |
| **CSP-safe** | Extension pages use strict Content Security Policy |

---

## Installation

1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `browser-assist-extension/` folder
4. Enter your license key in the extension popup Settings tab

### Prerequisites

- Chrome 116+ or Edge 116+ (Manifest V3 support)
- Valid Lonkero license key (for full features)

---

## Usage

Click the Lonkero icon in your browser toolbar to open the popup:

- **Overview tab** — Security grade, tech detection, scan buttons, View Source/Response
- **Findings tab** — View all detected vulnerabilities with severity filtering
- **Secrets tab** — Exposed keys, tokens, credentials (separate from findings)
- **Endpoints tab** — Discovered API endpoints, GraphQL, cloud storage
- **Requests tab** — View intercepted requests, edit and replay
- **Settings tab** — Configure scanning options and license key

### Console API

```javascript
// Run XSS scan on current page
xssScanner.scan()

// Run Merlin vulnerable library scan
merlin.scan()

// Test specific parameter for XSS
xssScanner.testParameter(location.href, 'search', 'test')

// GraphQL Fuzzer
gqlFuzz.fuzz()                      // Auto-discover and full scan
gqlFuzz.fuzz('/graphql')            // Scan specific endpoint
gqlFuzz.extractQueriesFromSource()  // Extract queries (no fuzzing)
gqlFuzz.quickFuzz()                 // Basic tests only
gqlFuzz.aggressiveFuzz()            // Full scan + DoS tests
gqlFuzz.getReport()                 // Get detailed results

// Smart Form Fuzzer v2.0
formFuzzer.discoverAndFuzzForms()   // Full smart fuzzing
formFuzzer.quickScan()              // Probe forms (no payloads)
formFuzzer.getReport()              // Get results

// CMS & Framework Scanner
cmsScanner.scan()                   // Full security scan
cmsScanner.quickScan()              // Quick CMS detection only
cmsScanner.getReport()              // Get results

// SQL Injection Scanner
sqlScanner.scan()                   // Scan current page parameters
sqlScanner.deepScan()               // Deep scan with crawling
```

### Detected Vulnerabilities

| Scanner | Detection | Proof |
|---------|-----------|-------|
| **Merlin** | jQuery 2.2.4 vulnerable | CVE-2020-11022, CVE-2020-11023 |
| **XSS Scanner** | Reflected XSS in `q` param | Unescaped `<` in HTML body context |
| **SQL Scanner** | Blind SQLi in `id` param | Time-based: SLEEP correlation r > 0.95 |
| **Tech Detection** | WordPress 6.4 | `/wp-content/`, `/wp-includes/` |
| **CMS Scanner** | WP user enumeration | `/wp-json/wp/v2/users` exposed |
| **Header Scoring** | Grade D (42/100) | Missing CSP, weak HSTS, no Permissions-Policy |
| **CSP Analysis** | CDN bypass via jsdelivr | `script-src` includes `cdn.jsdelivr.net` |
| **Cookie Audit** | Session cookie insecure | Missing SameSite, no __Host- prefix |
| **postMessage** | No origin validation | Listener accepts messages from any origin |
| **Comments** | Debug credentials in HTML | `<!-- TODO: remove admin/pass123 -->` |
| **Secrets** | Mapbox token in lazy chunk | `pk.eyJ...` in dynamically loaded JS |

---

## CLI Integration (Parasite Mode)

The extension integrates with the Lonkero CLI via WebSocket for enhanced scanning capabilities.

```bash
# Start scan with browser assist mode
lonkero scan https://example.com --browser-assist

# The CLI opens a WebSocket server on ws://127.0.0.1:9340/parasite
# Extension auto-connects and syncs findings bidirectionally
```

### Connection Flow

```
┌─────────────────────┐         ┌─────────────────────────┐
│   Lonkero CLI        │         │   Browser Extension      │
│   (Rust)             │         │   (Chrome MV3)           │
├──────────────────────┤         ├──────────────────────────┤
│ 1. Start WS server   │◄───────│ 2. Connect to WS         │
│ 3. Send challenge     │───────►│ 4. HMAC-sign challenge   │
│ 5. Verify HMAC        │◄───────│    with license key      │
│ 6. Send handshakeAck  │───────►│ 7. Validate license key  │
│    + license key      │        │    via server API         │
├──────────────────────┤         ├──────────────────────────┤
│ Receive findings      │◄──────►│ Send findings            │
│ Trigger deep scans    │───────►│ Execute scans            │
│ Set scope/targets     │───────►│ Apply scope rules        │
│ Receive tech info     │◄───────│ Share tech detection     │
└──────────────────────┘         └──────────────────────────┘
```

When connected:
- Extension findings are forwarded to CLI in real-time
- CLI can trigger deep scans through the extension
- Captured requests/responses flow to CLI for analysis
- Technologies detected are shared with scanner intelligence
- SSRF deny list blocks private IPs regardless of CLI scope

**Status indicator**: The extension popup shows **CLI Connected** when linked.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Service Worker (background.js)                                  │
│  • WebSocket client for CLI integration                         │
│  • License validation and state management                      │
│  • Request interception and proxy                               │
│  • HMAC-SHA256 authentication, SSRF deny list                   │
├─────────────────────────────────────────────────────────────────┤
│  Content Script (content.js) — runs in ISOLATED world            │
│  • Bridge between page context and extension                    │
│  • Per-session channel ID + nonce for message auth              │
│  • Finding field whitelist with truncation                      │
│  • Injects scanner scripts into MAIN world                      │
│  • Passive auto-scans: headers, cookies, JWTs, comments,        │
│    open redirects                                                │
│  • Dynamic script scanning via MutationObserver                  │
│  • CSP analysis with CDN bypass detection                        │
│  • Security header scoring (A-F grade)                           │
├─────────────────────────────────────────────────────────────────┤
│  MAIN World Scripts (injected into page context)                 │
│  ┌────────────────────────────────────────────────────────┐     │
│  │ merlin.js          — Vulnerable library detection       │     │
│  │ xss-scanner.js     — Proof-based XSS scanning           │     │
│  │ sql-scanner.js     — SQL injection detection             │     │
│  │ formfuzzer.js      — Smart form fuzzing                  │     │
│  │ graphql-fuzzer.js  — GraphQL security testing            │     │
│  │ cms-scanner.js     — CMS/framework vulnerability checks  │     │
│  │ framework-scanner.js — Technology fingerprinting          │     │
│  │ interceptors.js    — Request/response capture             │     │
│  │ dom-hooks.js       — DOM sink monitoring + postMessage enum │     │
│  └────────────────────────────────────────────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│  Popup (popup.html + popup.js + icons.js)                        │
│  • Findings viewer with severity filtering                      │
│  • Security header grade display (A+ through F)                  │
│  • View Source / View Response with raw + rendered modes         │
│  • Request editor and replay                                    │
│  • Settings and license key management                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Version History

### v3.7.0 — Passive Security Analysis
- **CSP analysis with CDN bypass detection** — 15+ known bypass domains (jsdelivr, unpkg, cdnjs, raw.githubusercontent.com, etc.), directive-by-directive parsing
- **Security header scoring (A-F grade)** — 8 categories, 100-point scale with weighted scoring displayed in popup stats grid
- **Enhanced cookie security audit** — Full attribute analysis via chrome.cookies API, SameSite/Secure/Domain/HttpOnly checks, `__Host-`/`__Secure-` prefix validation, JWT-in-cookie detection
- **postMessage enumeration** — Hooks addEventListener('message') to detect listeners without origin validation, logs outgoing messages, flags wildcard targetOrigin
- **Suspicious comments scanner** — Scans HTML comments and inline JS for 18 keywords (TODO, FIXME, HACK, password, secret, debug, admin, etc.), filters GTM/analytics noise
- **Dynamic script scanning** — MutationObserver catches lazy-loaded JS chunks (Next.js, Nuxt code splitting) for secret/endpoint detection
- **View Source / View Response** — Raw and sandboxed rendered HTML viewer in popup
- **reCAPTCHA key detection** — Site key and secret key pattern matching
- **Info-leak header detection** — X-Debug-Token, X-Backend-Server, X-ChromeLogger-Data
- **Auto-passive scanning** — Security headers, cookies, JWTs, open redirects, and comments scan automatically on page load

### v3.6.1 — Security Hardening
- **HMAC-SHA256 WebSocket authentication** — CLI proves identity via signed challenge-response
- **Server-side license validation** — Extension always validates license keys against the server
- **Per-install signing key** — Random 256-bit key replaces public `chrome.runtime.id`
- **Symbol-based scanner guards** — Prevents pages from disabling scanners via global pre-sets
- **SSRF deny list** — Blocks private IPs, loopback, link-local, cloud metadata in all modes
- **Finding field whitelist** — Explicit extraction with truncation replaces unsafe spread
- **DOM hooks hardened** — `configurable: false` on all hooks, Symbol-based dedup guards
- **Scan trigger validation** — Per-session nonce + channel required on all trigger messages
- **Deep scan clamping** — maxDepth/maxPages limits enforced regardless of input
- **DOM element cleanup** — License key delivery element removed after 2s
- **License input masked** — `type="password"` with `autocomplete="off"`
- **No external JS** — Removed all CDN/remote script dependencies
- **WebSocket message size limits** — 4 MB max message, 2 MB max frame

### v3.6.0
- **XSS Scanner v2.0** — Complete rewrite ported from Rust scanners:
  - Proof-Based Detection with 17 reflection contexts
  - DOM Differential Analysis
  - Static Taint Analysis (source → sink tracing)
  - 40+ XSS payloads including WAF evasion
  - Auto-scan on pages with URL parameters

### v3.5.4
- **CMS & Framework Security Scanner** — WordPress, Drupal, Joomla vulnerability checks
- **Fixed "Extension context invalidated" errors** — Graceful handling during reloads

### v3.5.3
- **UI Framework Form Detection** — Quasar, Vuetify, Element UI, Ant Design Vue, PrimeVue, Chakra UI

### v3.5.2
- **Smart Form Fuzzer v2.0** — HTTP method probing, early abort, SPA support, baseline comparison

### v3.5.1
- **GraphQL Source Code Query Extraction** — Extracts real queries from page JS
- **Form Fuzzer Server Fingerprinting** — Server info from error pages

### v3.5.0
- Security Headers Analysis, Cookie Security Audit, Open Redirect Detection
- JWT Decoder, Source Map Detection, Sensitive Paths, Mixed Content Detection

### v3.4.0
- Fixed technology detection, clickable findings, improved severity classification

### v3.3.0
- Initial Merlin.js, XSS scanner, technology detection, enlarged popup

---

## License

**Copyright &copy; 2026 Bountyy Oy. All rights reserved.**

This software is proprietary. Commercial use requires a valid license.

For licensing inquiries, visit [lonkero.bountyy.fi](https://lonkero.bountyy.fi/en) or contact [info@bountyy.fi](mailto:info@bountyy.fi).

---

**Made in Finland** 🇫🇮
