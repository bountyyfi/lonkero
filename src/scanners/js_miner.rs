// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Results from JS mining including vulnerabilities AND discovered attack surfaces
#[derive(Debug, Clone)]
pub struct JsMinerResults {
    pub vulnerabilities: Vec<Vulnerability>,
    pub tests_run: usize,
    /// Discovered API endpoints (full URLs)
    pub api_endpoints: HashSet<String>,
    /// Discovered parameters by endpoint
    pub parameters: HashMap<String, HashSet<String>>,
    /// Discovered form action URLs
    pub form_actions: HashSet<String>,
    /// GraphQL endpoints
    pub graphql_endpoints: HashSet<String>,
}

impl JsMinerResults {
    pub fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            tests_run: 0,
            api_endpoints: HashSet::new(),
            parameters: HashMap::new(),
            form_actions: HashSet::new(),
            graphql_endpoints: HashSet::new(),
        }
    }
}

/// Common third-party domains to skip (CDNs, analytics, widgets)
const THIRD_PARTY_DOMAINS: &[&str] = &[
    // Analytics & Tracking
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "analytics.google.com",
    "cloudflareinsights.com",
    "hotjar.com",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heap.io",
    "heapanalytics.com",
    "plausible.io",
    "fathom.com",
    "matomo.org",
    // Consent & Privacy
    "cookiebot.com",
    "onetrust.com",
    "cookielaw.org",
    "trustarc.com",
    "quantcast.com",
    "consentmanager.net",
    // CDNs & Libraries
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "polyfill.io",
    "code.jquery.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    // Chat & Support Widgets
    "intercom.io",
    "intercomcdn.com",
    "crisp.chat",
    "zendesk.com",
    "zdassets.com",
    "livechatinc.com",
    "tawk.to",
    "freshdesk.com",
    "drift.com",
    // Social & Sharing
    "facebook.net",
    "fbcdn.net",
    "twitter.com",
    "platform.twitter.com",
    "linkedin.com",
    "ads-twitter.com",
    "connect.facebook.net",
    // Ads & Marketing
    "adsrvr.org",
    "adform.net",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "amazon-adsystem.com",
    "bing.com",
    "bat.bing.com",
    // Payment (public SDKs)
    "js.stripe.com",
    "checkout.stripe.com",
    "js.braintreegateway.com",
    // Maps & Utilities
    "maps.googleapis.com",
    "maps.google.com",
    // Monitoring (public)
    "browser.sentry-cdn.com",
    "js.sentry-cdn.com",
    "cdn.ravenjs.com",
    // Other common third-party
    "recaptcha.net",
    "hcaptcha.com",
    "gstatic.com",
    "cloudflare.com",
];

/// Documentation domains to skip for API URL detection
const DOC_DOMAINS: &[&str] = &[
    "nextjs.org", "reactjs.org", "vuejs.org", "angular.io", "nodejs.org",
    "developer.mozilla.org", "docs.github.com", "stackoverflow.com",
    "medium.com", "dev.to", "w3.org", "json-schema.org", "schema.org",
    "npmjs.com", "github.com", "gitlab.com", "bitbucket.org",
];

/// Scanner for JavaScript source code analysis (sensitive data mining)
pub struct JsMinerScanner {
    http_client: Arc<HttpClient>,
}

impl JsMinerScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
        }
    }

    /// Check if URL is from a third-party domain that should be skipped
    fn is_third_party_url(&self, js_url: &str, target_host: &str) -> bool {
        let js_host = match url::Url::parse(js_url) {
            Ok(u) => u.host_str().unwrap_or("").to_lowercase(),
            Err(_) => return false,
        };

        // Same host - not third-party
        if js_host == target_host || js_host.ends_with(&format!(".{}", target_host)) {
            return false;
        }

        // Check against known third-party domains
        for domain in THIRD_PARTY_DOMAINS {
            if js_host == *domain || js_host.ends_with(&format!(".{}", domain)) {
                return true;
            }
        }

        // If it's a completely different domain, consider it third-party
        // unless it shares a common base domain
        let target_parts: Vec<&str> = target_host.split('.').collect();
        let js_parts: Vec<&str> = js_host.split('.').collect();

        // Extract base domain (last 2 parts for most TLDs)
        if target_parts.len() >= 2 && js_parts.len() >= 2 {
            let target_base = format!("{}.{}",
                target_parts[target_parts.len() - 2],
                target_parts[target_parts.len() - 1]);
            let js_base = format!("{}.{}",
                js_parts[js_parts.len() - 2],
                js_parts[js_parts.len() - 1]);

            // Same base domain - not third-party
            if target_base == js_base {
                return false;
            }
        }

        // Different domain - third-party
        true
    }

    /// Check if URL is documentation (should skip for API detection)
    fn is_documentation_url(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        for domain in DOC_DOMAINS {
            if url_lower.contains(domain) {
                return true;
            }
        }
        url_lower.contains("/docs/") || url_lower.contains("/documentation/") ||
        url_lower.contains("/reference/") || url_lower.contains("/api-reference/")
    }

    /// Run JavaScript mining scan (legacy method for backward compatibility)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let results = self.scan_full(url, config).await?;
        Ok((results.vulnerabilities, results.tests_run))
    }

    /// Run JavaScript mining scan with full results including discovered attack surfaces
    pub async fn scan_full(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<JsMinerResults> {
        info!("Starting JavaScript mining scan on {}", url);

        let mut results = JsMinerResults::new();
        let mut analyzed_urls: HashSet<String> = HashSet::new();
        let mut seen_evidence: HashSet<String> = HashSet::new(); // Deduplication

        // Parse target URL to get host
        let target_host = match url::Url::parse(url) {
            Ok(u) => u.host_str().unwrap_or("").to_lowercase(),
            Err(_) => return Ok(results),
        };

        // Get initial HTML response
        let initial_response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                info!("Failed to fetch initial page: {}", e);
                return Ok(results);
            }
        };

        let html = &initial_response.body;

        // Discover JavaScript files from HTML
        let js_files = self.discover_js_files(url, html);
        let total_js_count = js_files.len();
        info!("Discovered {} JavaScript files total", total_js_count);

        // Filter out third-party scripts
        let first_party_files: Vec<String> = js_files
            .into_iter()
            .filter(|js_url| !self.is_third_party_url(js_url, &target_host))
            .collect();

        let skipped_count = total_js_count - first_party_files.len();
        info!("Analyzing {} first-party JavaScript files (filtered {} third-party)",
              first_party_files.len(),
              skipped_count);

        // Analyze inline scripts
        results.tests_run += self.analyze_inline_scripts_full(html, url, &mut results, &mut seen_evidence);

        // Analyze JavaScript files (limit to 20 for performance)
        let files_to_analyze: Vec<String> = first_party_files.into_iter().take(20).collect();

        for js_url in &files_to_analyze {
            info!("[JS-Miner] Analyzing: {}", js_url);
        }

        for js_url in files_to_analyze {
            let tests = self.analyze_js_file_full(&js_url, &mut analyzed_urls, &mut results, &mut seen_evidence).await;
            results.tests_run += tests;
        }

        info!(
            "JavaScript mining scan completed: {} tests run, {} vulnerabilities found, {} API endpoints, {} parameters",
            results.tests_run,
            results.vulnerabilities.len(),
            results.api_endpoints.len(),
            results.parameters.values().map(|p| p.len()).sum::<usize>()
        );

        Ok(results)
    }

    /// Extended scan that also extracts API endpoints and parameters for injection testing
    pub async fn scan_with_extraction(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<JsMinerResults> {
        info!("Starting JavaScript mining scan with endpoint extraction on {}", url);

        let mut results = JsMinerResults::new();
        let mut analyzed_urls: HashSet<String> = HashSet::new();
        let mut seen_evidence: HashSet<String> = HashSet::new();

        // Parse target URL to get host
        let target_host = match url::Url::parse(url) {
            Ok(u) => u.host_str().unwrap_or("").to_lowercase(),
            Err(_) => return Ok(results),
        };

        // Get initial HTML response
        let initial_response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                info!("Failed to fetch initial page: {}", e);
                return Ok(results);
            }
        };

        let html = &initial_response.body;

        // Discover JavaScript files from HTML
        let js_files = self.discover_js_files(url, html);
        let total_js_count = js_files.len();
        info!("Discovered {} JavaScript files total", total_js_count);

        // Filter out third-party scripts
        let first_party_files: Vec<String> = js_files
            .into_iter()
            .filter(|js_url| !self.is_third_party_url(js_url, &target_host))
            .collect();

        // Analyze inline scripts
        results.tests_run += self.analyze_inline_scripts(html, url, &mut results.vulnerabilities, &mut seen_evidence);

        // Also extract from inline scripts
        self.extract_endpoints_and_params(html, &mut results);

        // Analyze JavaScript files (limit to 20 for performance)
        let files_to_analyze: Vec<String> = first_party_files.into_iter().take(20).collect();

        for js_url in files_to_analyze {
            let tests = self.analyze_js_file(&js_url, &mut analyzed_urls, &mut results.vulnerabilities, &mut seen_evidence).await;
            results.tests_run += tests;

            // Also extract endpoints and params from JS content
            if let Ok(response) = self.http_client.get(&js_url).await {
                self.extract_endpoints_and_params(&response.body, &mut results);
            }
        }

        // Count total parameters across all endpoints
        let total_params: usize = results.parameters.values().map(|s| s.len()).sum();

        info!(
            "JavaScript mining completed: {} vulns, {} API endpoints, {} GraphQL endpoints, {} params",
            results.vulnerabilities.len(),
            results.api_endpoints.len(),
            results.graphql_endpoints.len(),
            total_params
        );

        Ok(results)
    }

    /// Extract API endpoints and parameters from JavaScript content
    fn extract_endpoints_and_params(&self, content: &str, results: &mut JsMinerResults) {
        // Extract API URLs (fetch, axios, XMLHttpRequest patterns)
        let api_patterns = [
            r#"fetch\s*\(\s*["'`]([^"'`]+/api[^"'`]*)"#,
            r#"axios\.[a-z]+\s*\(\s*["'`]([^"'`]+)"#,
            r#"\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)"#,
            r#"baseURL\s*[=:]\s*["'`]([^"'`]+)"#,
            r#"apiUrl\s*[=:]\s*["'`]([^"'`]+)"#,
            r#"API_URL\s*[=:]\s*["'`]([^"'`]+)"#,
            r#"endpoint\s*[=:]\s*["'`]([^"'`]+)"#,
        ];

        for pattern in &api_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(content) {
                    if let Some(url) = cap.get(1) {
                        let url_str = url.as_str().to_string();
                        if !Self::is_documentation_url(&url_str) && url_str.len() > 5 {
                            results.api_endpoints.insert(url_str);
                        }
                    }
                }
            }
        }

        // Extract GraphQL endpoints
        if let Ok(regex) = Regex::new(r#"["'`](https?://[^"'`]+/graphql[^"'`]*)"#) {
            for cap in regex.captures_iter(content) {
                if let Some(url) = cap.get(1) {
                    let url_str = url.as_str().to_string();
                    if !Self::is_documentation_url(&url_str) {
                        results.graphql_endpoints.insert(url_str);
                    }
                }
            }
        }

        // Extract parameters from various patterns - be SELECTIVE to avoid noise
        let param_patterns = [
            // URL query parameters: ?param= or &param= (high confidence)
            r#"[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})="#,
            // Form field names: name="param" (high confidence)
            r#"name\s*=\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']"#,
            // GraphQL variables: $paramName (high confidence)
            r#"\$([a-zA-Z_][a-zA-Z0-9_]{1,30})"#,
            // Explicit input definitions: {name: "param"} (medium confidence)
            r#"\{\s*name\s*:\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']"#,
        ];

        // Security-relevant parameter names to specifically look for
        let security_params = [
            // Authentication/Authorization
            "id", "user_id", "userId", "uid", "account_id", "accountId",
            "email", "username", "password", "passwd", "pass", "pwd",
            "token", "access_token", "accessToken", "refresh_token", "refreshToken",
            "session", "sessionId", "session_id", "auth", "authorization",
            "api_key", "apiKey", "api_token", "apiToken", "secret", "key",
            // User input fields
            "name", "first_name", "firstName", "last_name", "lastName",
            "phone", "address", "comment", "message", "text", "content", "body",
            "title", "description", "subject", "note", "feedback",
            // Search/Filter
            "query", "search", "q", "s", "keyword", "term", "filter",
            // Pagination
            "page", "limit", "offset", "size", "per_page", "perPage",
            "sort", "order", "orderBy", "sortBy",
            // Navigation/Redirect (SSRF/Open Redirect)
            "url", "uri", "link", "href", "src", "dest", "destination",
            "redirect", "redirect_uri", "redirectUri", "return", "returnUrl",
            "return_to", "returnTo", "next", "goto", "target", "continue",
            "callback", "callbackUrl", "callback_url",
            // File operations (Path Traversal/LFI)
            "file", "filename", "path", "filepath", "dir", "directory",
            "template", "include", "page", "view", "load",
            // Data manipulation
            "data", "input", "value", "param", "args", "payload",
            "json", "xml", "action", "cmd", "command", "exec",
            // IDs and references
            "ref", "reference", "code", "status", "type", "category",
            "product_id", "productId", "item_id", "itemId", "order_id", "orderId",
        ];

        // Use "global" as key for parameters not tied to a specific endpoint
        let global_params = results.parameters.entry("global".to_string()).or_insert_with(HashSet::new);

        // Comprehensive JS/framework noise filter
        let js_noise: HashSet<&str> = [
            // JavaScript keywords
            "function", "return", "const", "let", "var", "this", "true", "false",
            "null", "undefined", "async", "await", "import", "export", "default",
            "class", "extends", "constructor", "prototype", "new", "delete", "typeof",
            "instanceof", "in", "of", "if", "else", "for", "while", "do", "switch",
            "case", "break", "continue", "try", "catch", "finally", "throw", "yield",
            "static", "get", "set", "super", "with", "debugger", "void",

            // Common JS methods/properties
            "toString", "valueOf", "length", "push", "pop", "shift", "unshift",
            "map", "filter", "reduce", "forEach", "find", "findIndex", "some", "every",
            "slice", "splice", "concat", "join", "split", "indexOf", "includes",
            "then", "catch", "finally", "resolve", "reject", "all", "race",
            "keys", "values", "entries", "assign", "freeze", "seal", "create",
            "parse", "stringify", "apply", "call", "bind", "hasOwnProperty",
            "isArray", "isObject", "isString", "isNumber", "isFunction", "isBoolean",
            "from", "of", "fill", "flat", "flatMap", "sort", "reverse", "copyWithin",

            // React hooks and internals
            "props", "state", "setState", "useState", "useEffect", "useCallback",
            "useMemo", "useRef", "useContext", "useReducer", "useLayoutEffect",
            "useImperativeHandle", "useDebugValue", "useDeferredValue", "useTransition",
            "useId", "useSyncExternalStore", "useInsertionEffect", "forwardRef",
            "createContext", "createRef", "createRoot", "createElement", "cloneElement",
            "isValidElement", "Children", "Fragment", "StrictMode", "Suspense", "lazy",
            "memo", "startTransition", "flushSync", "hydrate", "render", "unmountComponentAtNode",
            "Component", "PureComponent", "shouldComponentUpdate", "componentDidMount",
            "componentDidUpdate", "componentWillUnmount", "getDerivedStateFromProps",
            "getSnapshotBeforeUpdate", "componentDidCatch", "getDerivedStateFromError",

            // Vue.js
            "computed", "watch", "watchEffect", "methods", "data", "template", "style",
            "setup", "onMounted", "onUnmounted", "onUpdated", "onBeforeMount",
            "onBeforeUnmount", "onBeforeUpdate", "onActivated", "onDeactivated",
            "onErrorCaptured", "onRenderTracked", "onRenderTriggered", "onServerPrefetch",
            "ref", "reactive", "readonly", "toRef", "toRefs", "isRef", "unref", "shallowRef",
            "triggerRef", "customRef", "shallowReactive", "shallowReadonly", "toRaw",
            "markRaw", "effectScope", "getCurrentScope", "onScopeDispose", "provide", "inject",
            "defineComponent", "defineAsyncComponent", "defineProps", "defineEmits",
            "defineExpose", "withDefaults", "useSlots", "useAttrs", "nextTick",
            "vModel", "vShow", "vIf", "vFor", "vBind", "vOn", "vSlot",

            // Angular
            "ngOnInit", "ngOnDestroy", "ngOnChanges", "ngDoCheck", "ngAfterContentInit",
            "ngAfterContentChecked", "ngAfterViewInit", "ngAfterViewChecked",
            "Injectable", "Component", "Directive", "Pipe", "NgModule", "Input", "Output",
            "ViewChild", "ViewChildren", "ContentChild", "ContentChildren", "HostBinding",
            "HostListener", "EventEmitter", "ChangeDetectorRef", "ElementRef", "TemplateRef",
            "ViewContainerRef", "Renderer2", "Injector", "NgZone", "ApplicationRef",
            "FormControl", "FormGroup", "FormArray", "Validators", "AbstractControl",
            "HttpClient", "HttpHeaders", "HttpParams", "HttpInterceptor",
            "ActivatedRoute", "Router", "RouterModule", "Routes", "CanActivate",
            "Observable", "Subject", "BehaviorSubject", "ReplaySubject", "AsyncSubject",
            "pipe", "subscribe", "unsubscribe", "switchMap", "mergeMap", "concatMap",
            "exhaustMap", "tap", "map", "filter", "take", "takeUntil", "debounceTime",
            "distinctUntilChanged", "catchError", "retry", "finalize", "shareReplay",

            // Next.js / Nuxt.js
            "getServerSideProps", "getStaticProps", "getStaticPaths", "getInitialProps",
            "useRouter", "useSearchParams", "usePathname", "useParams", "useSelectedLayoutSegment",
            "notFound", "redirect", "permanentRedirect", "revalidatePath", "revalidateTag",
            "generateStaticParams", "generateMetadata", "generateViewport",
            "NextRequest", "NextResponse", "NextPage", "NextApiRequest", "NextApiResponse",
            "asyncData", "fetch", "head", "layout", "middleware", "plugins", "nuxtApp",
            "useAsyncData", "useFetch", "useLazyFetch", "useHead", "useState", "useNuxtApp",
            "defineNuxtConfig", "defineNuxtPlugin", "defineNuxtRouteMiddleware",
            "isServer", "isClient", "isBrowser", "isNode", "isDev", "isProd",

            // Node.js / Express
            "module", "exports", "require", "define", "factory", "__dirname", "__filename",
            "process", "global", "Buffer", "console", "setTimeout", "setInterval",
            "clearTimeout", "clearInterval", "setImmediate", "clearImmediate",
            "express", "app", "router", "middleware", "bodyParser", "cookieParser",
            "cors", "helmet", "morgan", "passport", "session", "multer",

            // TypeScript
            "interface", "type", "enum", "namespace", "declare", "readonly", "abstract",
            "implements", "private", "protected", "public", "override", "as", "is",
            "keyof", "infer", "never", "unknown", "any", "object", "string", "number",
            "boolean", "symbol", "bigint", "Record", "Partial", "Required", "Pick",
            "Omit", "Exclude", "Extract", "NonNullable", "ReturnType", "Parameters",

            // Webpack / Build tools
            "webpack", "chunk", "chunks", "bundle", "loader", "plugin", "entry", "output",
            "resolve", "alias", "extensions", "devServer", "optimization", "splitChunks",
            "miniCssExtractPlugin", "htmlWebpackPlugin", "definePlugin", "hotModuleReplacement",
            "__webpack_require__", "__webpack_exports__", "__webpack_modules__",
            "webpackChunkName", "webpackPrefetch", "webpackPreload",

            // DOM / Browser APIs
            "document", "window", "navigator", "location", "history", "localStorage",
            "sessionStorage", "indexedDB", "fetch", "XMLHttpRequest", "WebSocket",
            "addEventListener", "removeEventListener", "dispatchEvent", "preventDefault",
            "stopPropagation", "target", "currentTarget", "srcElement", "relatedTarget",
            "querySelector", "querySelectorAll", "getElementById", "getElementsByClassName",
            "getElementsByTagName", "createElement", "createTextNode", "appendChild",
            "removeChild", "insertBefore", "replaceChild", "cloneNode", "getAttribute",
            "setAttribute", "removeAttribute", "classList", "className", "innerHTML",
            "innerText", "textContent", "parentNode", "parentElement", "childNodes",
            "children", "firstChild", "lastChild", "nextSibling", "previousSibling",
            "offsetWidth", "offsetHeight", "offsetTop", "offsetLeft", "clientWidth",
            "clientHeight", "scrollWidth", "scrollHeight", "scrollTop", "scrollLeft",
            "getBoundingClientRect", "getComputedStyle", "requestAnimationFrame",
            "cancelAnimationFrame", "MutationObserver", "IntersectionObserver",
            "ResizeObserver", "PerformanceObserver", "CustomEvent", "Event",

            // Common libraries (lodash, axios, moment, etc.)
            "lodash", "underscore", "axios", "moment", "dayjs", "luxon", "date",
            "jquery", "d3", "chart", "echarts", "highcharts", "three", "pixi",
            "socket", "io", "emit", "on", "off", "once", "broadcast",
            "debounce", "throttle", "memoize", "curry", "compose", "pipe",
            "get", "set", "has", "merge", "cloneDeep", "isEqual", "isEmpty",
            "pick", "omit", "groupBy", "sortBy", "orderBy", "uniq", "uniqBy",

            // State management (Redux, MobX, Zustand, Pinia)
            "dispatch", "getState", "subscribe", "replaceReducer", "combineReducers",
            "createStore", "applyMiddleware", "compose", "bindActionCreators",
            "useSelector", "useDispatch", "useStore", "connect", "mapStateToProps",
            "mapDispatchToProps", "action", "reducer", "selector", "slice", "thunk",
            "saga", "observable", "autorun", "reaction", "when", "makeAutoObservable",
            "makeObservable", "runInAction", "flow", "defineStore", "storeToRefs",

            // Testing
            "describe", "it", "test", "expect", "beforeEach", "afterEach", "beforeAll",
            "afterAll", "jest", "mock", "spy", "fn", "spyOn", "mockImplementation",
            "mockReturnValue", "mockResolvedValue", "mockRejectedValue", "toEqual",
            "toBe", "toHaveBeenCalled", "toHaveBeenCalledWith", "toThrow", "toMatch",

            // Common single/double letter variable names (minified code)
            "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            "a", "b", "c", "d", "e", "f", "g", "h",
            "el", "ev", "fn", "cb", "rx", "tx", "id", "pk", "fk", "db", "ui", "vm", "vn",
            "aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", "am",
            "ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bk", "bl", "bm",
            "ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch", "ci", "cj", "ck", "cl", "cm",

            // Common variable/property names that aren't input parameters
            "err", "res", "req", "ctx", "obj", "arr", "val", "key", "idx", "len", "str",
            "num", "bool", "func", "args", "self", "that", "base", "root", "node", "tree",
            "item", "items", "index", "result", "results", "response", "request",
            "error", "errors", "success", "failure", "pending", "loading", "loaded",
            "options", "config", "settings", "params", "attrs", "slots", "refs",
            "context", "store", "router", "route", "routes", "path", "paths",
            "parent", "child", "children", "sibling", "ancestor", "descendant",
            "prev", "next", "first", "last", "current", "selected", "active", "disabled",
            "visible", "hidden", "open", "closed", "expanded", "collapsed",
            "width", "height", "top", "left", "right", "bottom", "margin", "padding",
            "color", "background", "border", "font", "size", "weight", "opacity",
            "transform", "transition", "animation", "duration", "delay", "easing",
            "min", "max", "step", "count", "total", "sum", "avg", "mean", "median",
            "start", "end", "begin", "finish", "init", "destroy", "reset", "clear",
            "add", "remove", "insert", "delete", "update", "edit", "save", "load",
            "show", "hide", "toggle", "enable", "disable", "lock", "unlock",
            "on", "off", "yes", "no", "ok", "cancel", "confirm", "submit", "abort",
            "handler", "handlers", "listener", "listeners", "callback", "callbacks",
            "event", "events", "trigger", "emit", "fire", "notify", "broadcast",
            "model", "models", "view", "views", "controller", "controllers",
            "service", "services", "factory", "factories", "provider", "providers",
            "util", "utils", "helper", "helpers", "common", "shared", "core", "base",
            "api", "http", "https", "ws", "wss", "tcp", "udp", "host", "port",
            "env", "dev", "prod", "test", "stage", "local", "remote", "debug", "release",
            // Config/state words
            "stable", "unstable", "beta", "alpha", "latest", "legacy", "deprecated",
            "active", "inactive", "valid", "invalid", "dirty", "pristine", "clean",
            "pending", "complete", "finished", "done", "ready", "busy", "idle",
            "locked", "unlocked", "frozen", "mutable", "immutable",
            "sync", "lazy", "eager", "strict", "loose", "safe", "unsafe",
            "internal", "external", "scoped", "isolated", "sandboxed",
            "dynamic", "fixed", "absolute", "relative", "sticky", "fluid",
            "primary", "secondary", "tertiary", "custom", "manual",
            "horizontal", "vertical", "inline", "block", "none", "both",
            "unique", "duplicate", "cloned", "cached", "persisted", "transient",
            "ascending", "descending", "asc", "desc", "forward", "backward", "reverse",
            "native", "polyfill", "fallback", "shim", "mock", "stub", "fake", "real",

            // HTML attributes (not input parameters)
            "draggable", "droppable", "sortable", "resizable", "selectable", "editable",
            "disabled", "enabled", "readonly", "required", "optional", "checked", "selected",
            "hidden", "visible", "collapsed", "expanded", "focused", "blurred",
            "placeholder", "autofocus", "autocomplete", "spellcheck", "contenteditable",
            "tabindex", "accesskey", "translate", "dir", "lang", "title", "alt",
            "href", "src", "srcset", "sizes", "media", "rel", "target", "download",
            "width", "height", "min", "max", "step", "pattern", "maxlength", "minlength",
            "cols", "rows", "wrap", "multiple", "accept", "capture", "form", "formaction",
            "enctype", "method", "novalidate", "formnovalidate", "formtarget",
            "async", "defer", "crossorigin", "integrity", "referrerpolicy", "loading",
            "decoding", "fetchpriority", "blocking", "elementtiming",

            // CSS properties commonly found in JS
            "display", "position", "overflow", "visibility", "opacity", "zIndex",
            "margin", "padding", "border", "outline", "background", "color",
            "font", "fontSize", "fontWeight", "fontFamily", "fontStyle",
            "textAlign", "textDecoration", "textTransform", "lineHeight", "letterSpacing",
            "flex", "flexDirection", "flexWrap", "justifyContent", "alignItems", "alignContent",
            "gridTemplate", "gridColumn", "gridRow", "gap", "order", "flexGrow", "flexShrink",
            "transform", "transition", "animation", "cursor", "pointerEvents", "userSelect",
            "boxShadow", "borderRadius", "boxSizing", "whiteSpace", "wordBreak", "wordWrap",

            // UI Framework components (Quasar, Vuetify, Element, Material, etc.)
            // Quasar (Q prefix)
            "QBadge", "QBtn", "QCard", "QCardSection", "QCardActions", "QCheckbox",
            "QChip", "QDialog", "QDrawer", "QExpansionItem", "QField", "QForm",
            "QHeader", "QIcon", "QImg", "QInput", "QItem", "QItemSection", "QItemLabel",
            "QLayout", "QList", "QMenu", "QPage", "QPageContainer", "QPageSticky",
            "QPopupProxy", "QRadio", "QRouteTab", "QScrollArea", "QSelect", "QSeparator",
            "QSlider", "QSpace", "QSpinner", "QSplitter", "QStep", "QStepper",
            "QTab", "QTable", "QTabs", "QTabPanel", "QTabPanels", "QTimeline",
            "QToggle", "QToolbar", "QToolbarTitle", "QTooltip", "QTree", "QUploader",
            "QVideo", "QVirtualScroll",
            // Vuetify (V prefix)
            "VApp", "VAppBar", "VAlert", "VAutocomplete", "VAvatar", "VBadge",
            "VBottomNavigation", "VBreadcrumbs", "VBtn", "VBtnToggle", "VCalendar",
            "VCard", "VCardActions", "VCardText", "VCardTitle", "VCarousel",
            "VCheckbox", "VChip", "VCol", "VCombobox", "VContainer", "VDataTable",
            "VDialog", "VDivider", "VExpansionPanel", "VExpansionPanels", "VFileInput",
            "VFooter", "VForm", "VIcon", "VImg", "VInput", "VItem", "VItemGroup",
            "VList", "VListItem", "VListItemAction", "VListItemContent", "VListItemTitle",
            "VMain", "VMenu", "VNavigationDrawer", "VOverlay", "VPagination",
            "VProgressCircular", "VProgressLinear", "VRadio", "VRadioGroup", "VRating",
            "VRow", "VSelect", "VSheet", "VSlideGroup", "VSlider", "VSnackbar",
            "VSpacer", "VSpeedDial", "VStepper", "VSwitch", "VSystemBar", "VTab",
            "VTable", "VTabs", "VTextarea", "VTextField", "VTimeline", "VToolbar",
            "VTooltip", "VTreeview", "VWindow",
            // Element UI (El prefix)
            "ElAlert", "ElAside", "ElAutocomplete", "ElAvatar", "ElBacktop", "ElBadge",
            "ElBreadcrumb", "ElButton", "ElButtonGroup", "ElCalendar", "ElCard",
            "ElCarousel", "ElCascader", "ElCheckbox", "ElCheckboxGroup", "ElCol",
            "ElCollapse", "ElColorPicker", "ElContainer", "ElDatePicker", "ElDialog",
            "ElDivider", "ElDrawer", "ElDropdown", "ElEmpty", "ElFooter", "ElForm",
            "ElFormItem", "ElHeader", "ElIcon", "ElImage", "ElInput", "ElInputNumber",
            "ElLink", "ElMain", "ElMenu", "ElMenuItem", "ElOption", "ElPageHeader",
            "ElPagination", "ElPopconfirm", "ElPopover", "ElProgress", "ElRadio",
            "ElRadioGroup", "ElRate", "ElResult", "ElRow", "ElScrollbar", "ElSelect",
            "ElSkeleton", "ElSlider", "ElSpace", "ElStep", "ElSteps", "ElSubmenu",
            "ElSwitch", "ElTable", "ElTableColumn", "ElTabPane", "ElTabs", "ElTag",
            "ElTimePicker", "ElTimeline", "ElTimeSelect", "ElTooltip", "ElTransfer",
            "ElTree", "ElUpload",
            // Ant Design
            "Alert", "Anchor", "AutoComplete", "Avatar", "BackTop", "Badge", "Breadcrumb",
            "Button", "Calendar", "Card", "Carousel", "Cascader", "Checkbox", "Col",
            "Collapse", "Comment", "ConfigProvider", "DatePicker", "Descriptions",
            "Divider", "Drawer", "Dropdown", "Empty", "Form", "Grid", "Image", "Input",
            "InputNumber", "Layout", "List", "Mentions", "Menu", "Message", "Modal",
            "Notification", "PageHeader", "Pagination", "Popconfirm", "Popover",
            "Progress", "Radio", "Rate", "Result", "Row", "Segmented", "Select",
            "Skeleton", "Slider", "Space", "Spin", "Statistic", "Steps", "Switch",
            "Table", "Tabs", "Tag", "TimePicker", "Timeline", "Tooltip", "Transfer",
            "Tree", "TreeSelect", "Typography", "Upload",
            // Material UI (Mui prefix and common)
            "MuiAlert", "MuiAppBar", "MuiAutocomplete", "MuiAvatar", "MuiBackdrop",
            "MuiBadge", "MuiBottomNavigation", "MuiBox", "MuiBreadcrumbs", "MuiButton",
            "MuiButtonGroup", "MuiCard", "MuiCardActions", "MuiCardContent", "MuiCardHeader",
            "MuiCardMedia", "MuiCheckbox", "MuiChip", "MuiCircularProgress", "MuiCollapse",
            "MuiContainer", "MuiDialog", "MuiDivider", "MuiDrawer", "MuiFab", "MuiFormControl",
            "MuiFormControlLabel", "MuiGrid", "MuiIcon", "MuiIconButton", "MuiInput",
            "MuiInputAdornment", "MuiInputBase", "MuiInputLabel", "MuiLinearProgress",
            "MuiLink", "MuiList", "MuiListItem", "MuiListItemButton", "MuiListItemIcon",
            "MuiListItemText", "MuiMenu", "MuiMenuItem", "MuiModal", "MuiOutlinedInput",
            "MuiPagination", "MuiPaper", "MuiPopover", "MuiPopper", "MuiRadio",
            "MuiRadioGroup", "MuiRating", "MuiSelect", "MuiSkeleton", "MuiSlider",
            "MuiSnackbar", "MuiSpeedDial", "MuiStack", "MuiStep", "MuiStepper", "MuiSwitch",
            "MuiTab", "MuiTable", "MuiTableBody", "MuiTableCell", "MuiTableHead",
            "MuiTableRow", "MuiTabs", "MuiTextField", "MuiToggleButton", "MuiToolbar",
            "MuiTooltip", "MuiTypography",
            // Chakra UI
            "ChakraProvider", "Box", "Flex", "Grid", "SimpleGrid", "Stack", "HStack",
            "VStack", "Center", "Container", "Spacer", "Wrap", "WrapItem",
            // Bootstrap Vue
            "BAlert", "BBadge", "BBreadcrumb", "BButton", "BButtonGroup", "BCard",
            "BCardBody", "BCardHeader", "BCardText", "BCarousel", "BCol", "BCollapse",
            "BContainer", "BDropdown", "BForm", "BFormGroup", "BFormInput", "BFormSelect",
            "BIcon", "BImg", "BInputGroup", "BLink", "BListGroup", "BModal", "BNav",
            "BNavbar", "BPagination", "BProgress", "BRow", "BSpinner", "BTab", "BTable",
            "BTabs", "BToast", "BTooltip",
            // PrimeVue/PrimeReact
            "Accordion", "AccordionTab", "AutoComplete", "BlockUI", "Breadcrumb",
            "ButtonGroup", "Calendar", "Carousel", "Chart", "Checkbox", "Chip", "Chips",
            "ColorPicker", "Column", "ColumnGroup", "ConfirmDialog", "ConfirmPopup",
            "ContextMenu", "DataTable", "DataView", "DeferredContent", "Dialog",
            "Divider", "Dock", "Dropdown", "DynamicDialog", "Editor", "Fieldset",
            "FileUpload", "Galleria", "Image", "InlineMessage", "Inplace", "InputMask",
            "InputNumber", "InputSwitch", "InputText", "Knob", "Listbox", "MegaMenu",
            "Menubar", "Message", "MultiSelect", "OrderList", "OrganizationChart",
            "OverlayPanel", "Paginator", "Panel", "PanelMenu", "Password", "PickList",
            "ProgressBar", "ProgressSpinner", "RadioButton", "Rating", "Ripple",
            "ScrollPanel", "ScrollTop", "SelectButton", "Sidebar", "Skeleton", "Slider",
            "SpeedDial", "SplitButton", "Splitter", "Steps", "TabMenu", "TabPanel",
            "TabView", "Tag", "Terminal", "Textarea", "TieredMenu", "Toast", "ToggleButton",
            "Toolbar", "Tooltip", "Tree", "TreeSelect", "TreeTable", "TriStateCheckbox",
            "VirtualScroller",
        ].iter().cloned().collect();

        // Additional check: filter out PascalCase names that look like components/classes
        let is_likely_component = |s: &str| -> bool {
            if s.len() < 3 { return false; }
            let chars: Vec<char> = s.chars().collect();
            // Must start with uppercase
            if !chars[0].is_uppercase() { return false; }

            // Count uppercase letters - components typically have 2+ (PascalCase)
            let uppercase_count = chars.iter().filter(|c| c.is_uppercase()).count();
            if uppercase_count >= 2 {
                return true;
            }

            // Common component/class name patterns (contains these = likely not a param)
            let class_patterns = [
                // UI Components
                "Input", "Button", "Form", "Modal", "Dialog", "Table", "List",
                "Card", "Menu", "Icon", "Text", "Label", "Select", "Check",
                "Radio", "Switch", "Slider", "Date", "Time", "Color", "File",
                "Upload", "Download", "Nav", "Tab", "Panel", "Drawer", "Popup",
                "Tooltip", "Toast", "Alert", "Badge", "Avatar", "Progress",
                "Spinner", "Loading", "Skeleton", "Empty", "Error", "Success",
                "Warning", "Info", "Header", "Footer", "Sidebar", "Content",
                "Layout", "Container", "Row", "Col", "Grid", "Flex", "Box",
                "Stack", "Wrap", "Space", "Divider", "Separator",
                // Common class suffixes (Util, Helper, Service, etc.)
                "Util", "Utils", "Helper", "Helpers", "Service", "Services",
                "Handler", "Handlers", "Manager", "Managers", "Controller",
                "Factory", "Provider", "Adapter", "Wrapper", "Builder",
                "Parser", "Formatter", "Validator", "Converter", "Mapper",
                "Reducer", "Selector", "Middleware", "Interceptor", "Guard",
                "Resolver", "Directive", "Pipe", "Module", "Component",
                "Plugin", "Extension", "Mixin", "Decorator", "Annotation",
                // Apollo/GraphQL specific
                "Apollo", "Query", "Mutation", "Subscription", "Fragment",
                "Client", "Cache", "Link", "Schema", "Resolver",
                // State management
                "Store", "State", "Action", "Reducer", "Effect", "Saga",
                "Slice", "Thunk", "Observable", "Subject",
                // Common prefixes/suffixes
                "use", "get", "set", "is", "has", "can", "should", "will",
                "on", "handle", "fetch", "load", "save", "update", "delete",
                "create", "init", "setup", "config", "register", "unregister",
                "Params", "Options", "Config", "Settings", "Props", "Args",
                "Data", "Info", "Meta", "Context", "Ref", "Refs",
            ];
            for pattern in class_patterns {
                if s.contains(pattern) {
                    return true;
                }
            }
            false
        };

        // Check if string looks like a minified variable (e.g., p192, t45, e0, n123)
        let is_minified_var = |s: &str| -> bool {
            let chars: Vec<char> = s.chars().collect();
            if chars.len() < 2 || chars.len() > 6 { return false; }
            // Pattern: 1-2 lowercase letters followed by digits
            let letter_count = chars.iter().take_while(|c| c.is_ascii_lowercase()).count();
            if letter_count == 0 || letter_count > 2 { return false; }
            let rest = &chars[letter_count..];
            !rest.is_empty() && rest.iter().all(|c| c.is_ascii_digit())
        };

        // Extract from URL patterns only (most reliable)
        for pattern in &param_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(content) {
                    if let Some(param) = cap.get(1) {
                        let param_str = param.as_str();
                        // Filter out JS noise, component names, minified vars
                        if !js_noise.contains(param_str)
                            && param_str.len() >= 2
                            && !is_likely_component(param_str)
                            && !is_minified_var(param_str) {
                            global_params.insert(param_str.to_string());
                        }
                    }
                }
            }
        }

        // Only add security-relevant params if they appear in likely input contexts
        for param in security_params {
            // Look for params in likely input contexts, not just any occurrence
            let input_patterns = [
                format!(r#"name\s*[=:]\s*["']{}["']"#, param),
                format!(r#"[?&]{}="#, param),
                format!(r#"\${}[^a-zA-Z0-9_]"#, param),
            ];
            for pat in &input_patterns {
                if let Ok(re) = Regex::new(&pat) {
                    if re.is_match(content) {
                        global_params.insert(param.to_string());
                        break;
                    }
                }
            }
        }

        // Extract form field definitions (React/Vue style) - add to global params
        let form_field_patterns = [
            r#"<input[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"<textarea[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"<select[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"formControlName\s*=\s*["']([^"']+)["']"#,  // Angular
            r#"v-model\s*=\s*["']([^"']+)["']"#,          // Vue
            r#"register\s*\(\s*["']([^"']+)["']"#,        // React Hook Form
        ];

        for pattern in form_field_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(content) {
                    if let Some(field) = cap.get(1) {
                        global_params.insert(field.as_str().to_string());
                    }
                }
            }
        }

        // Extract form action URLs
        let form_action_patterns = [
            r#"<form[^>]*action\s*=\s*["']([^"']+)["']"#,
            r#"action\s*[=:]\s*["']([^"']+)["']"#,
        ];

        for pattern in form_action_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(content) {
                    if let Some(action) = cap.get(1) {
                        let action_str = action.as_str().to_string();
                        if !action_str.is_empty() && action_str != "#" {
                            results.form_actions.insert(action_str);
                        }
                    }
                }
            }
        }
    }

    /// Discover JavaScript files from HTML
    fn discover_js_files(&self, base_url: &str, html: &str) -> Vec<String> {
        let mut js_files = Vec::new();

        // Parse base URL
        let url_obj = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return js_files,
        };

        let origin = format!("{}://{}", url_obj.scheme(), url_obj.host_str().unwrap_or(""));

        // Extract script tags with src attribute (flexible regex)
        // Matches: <script src="..."> <script type="module" src="..."> etc
        let script_regex = Regex::new(r#"<script[^>]*\ssrc\s*=\s*["']?([^"'\s>]+)"#).unwrap();
        for cap in script_regex.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let js_url = self.resolve_js_url(&origin, &url_obj, src.as_str());
                if !js_files.contains(&js_url) {
                    info!("[JS-Miner] Found script: {}", js_url);
                    js_files.push(js_url);
                }
            }
        }

        // Also find JS URLs in link preload tags
        let preload_regex = Regex::new(r#"<link[^>]*\shref\s*=\s*["']?([^"'\s>]+\.js[^"'\s>]*)"#).unwrap();
        for cap in preload_regex.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                let js_url = self.resolve_js_url(&origin, &url_obj, href.as_str());
                if !js_files.contains(&js_url) {
                    info!("[JS-Miner] Found preload script: {}", js_url);
                    js_files.push(js_url);
                }
            }
        }

        // Find any .js URLs in the HTML (catch dynamic imports, webpack chunks, etc.)
        let any_js_regex = Regex::new(r#"["']([^"'\s]*\.js)(?:\?[^"'\s]*)?"#).unwrap();
        for cap in any_js_regex.captures_iter(html) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                // Skip very short paths and data URIs
                if path_str.len() > 3 && !path_str.starts_with("data:") {
                    let js_url = self.resolve_js_url(&origin, &url_obj, path_str);
                    if !js_files.contains(&js_url) {
                        js_files.push(js_url);
                    }
                }
            }
        }

        js_files
    }

    /// Resolve a JS URL to absolute
    fn resolve_js_url(&self, origin: &str, url_obj: &url::Url, path: &str) -> String {
        if path.starts_with("//") {
            format!("{}:{}", url_obj.scheme(), path)
        } else if path.starts_with('/') {
            format!("{}{}", origin, path)
        } else if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}/{}", origin, path)
        }
    }

    /// Analyze inline scripts in HTML
    fn analyze_inline_scripts(&self, html: &str, location: &str, vulnerabilities: &mut Vec<Vulnerability>, seen_evidence: &mut HashSet<String>) -> usize {
        let mut tests_run = 0;

        let inline_script_regex = Regex::new(r#"<script[^>]*>([\s\S]*?)</script>"#).unwrap();

        for (index, cap) in inline_script_regex.captures_iter(html).enumerate() {
            if let Some(script_content) = cap.get(1) {
                let content = script_content.as_str();
                if content.trim().len() > 50 {
                    let inline_location = format!("{}#inline-{}", location, index);
                    tests_run += 1;
                    self.analyze_js_content(content, &inline_location, vulnerabilities, seen_evidence);
                }
            }
        }

        tests_run
    }

    /// Analyze inline scripts with full results
    fn analyze_inline_scripts_full(&self, html: &str, location: &str, results: &mut JsMinerResults, seen_evidence: &mut HashSet<String>) -> usize {
        let mut tests_run = 0;

        let inline_script_regex = Regex::new(r#"<script[^>]*>([\s\S]*?)</script>"#).unwrap();

        for (index, cap) in inline_script_regex.captures_iter(html).enumerate() {
            if let Some(script_content) = cap.get(1) {
                let content = script_content.as_str();
                if content.trim().len() > 50 {
                    let inline_location = format!("{}#inline-{}", location, index);
                    tests_run += 1;
                    self.analyze_js_content_full(content, &inline_location, results, seen_evidence);
                }
            }
        }

        tests_run
    }

    /// Analyze a JavaScript file with full results
    async fn analyze_js_file_full(&self, js_url: &str, analyzed_urls: &mut HashSet<String>, results: &mut JsMinerResults, seen_evidence: &mut HashSet<String>) -> usize {
        if analyzed_urls.contains(js_url) {
            return 0;
        }

        analyzed_urls.insert(js_url.to_string());

        match self.http_client.get(js_url).await {
            Ok(response) => {
                let content_type = response.headers.get("content-type")
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();

                if content_type.contains("javascript") || content_type.contains("application/json") || response.body.len() > 0 {
                    if response.body.len() <= 30 * 1024 * 1024 {
                        let before_count = results.vulnerabilities.len();
                        self.analyze_js_content_full(&response.body, js_url, results, seen_evidence);
                        let found = results.vulnerabilities.len() - before_count;
                        if found > 0 {
                            info!("[JS-Miner] Found {} issues in {}", found, js_url);
                        }
                        return 1;
                    }
                }
            }
            Err(e) => {
                info!("Failed to fetch JS file {}: {}", js_url, e);
            }
        }

        0
    }

    /// Analyze JavaScript content with full results (vulns + attack surfaces)
    fn analyze_js_content_full(&self, content: &str, location: &str, results: &mut JsMinerResults, seen_evidence: &mut HashSet<String>) {
        // First extract attack surfaces (endpoints, parameters)
        self.extract_attack_surfaces(content, location, results);

        // Then run vulnerability detection
        self.analyze_js_content(content, location, &mut results.vulnerabilities, seen_evidence);
    }

    /// Extract API endpoints, parameters, and form actions from JS content
    fn extract_attack_surfaces(&self, content: &str, _location: &str, results: &mut JsMinerResults) {
        // Extract API endpoints with path parameters
        // Pattern: /api/something or /v1/something or /graphql
        if let Some(endpoints) = self.scan_pattern(content, r#"['"`](/(?:api|v[0-9]+|graphql)[^'"`\s<>]{0,100})['"`]"#, "API Endpoint") {
            for endpoint in endpoints.into_iter().take(50) {
                let clean = endpoint.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if clean.len() > 3 && !clean.contains("..") {
                    results.api_endpoints.insert(clean.to_string());

                    // Extract path parameters like :id or {id}
                    self.extract_path_params(clean, results);
                }
            }
        }

        // Extract full API URLs
        if let Some(urls) = self.scan_pattern(content, r#"https?://[a-zA-Z0-9.\-]+[:/][^\s"'<>]*(?:api|v[0-9]+|graphql)[^\s"'<>]*"#, "API URL") {
            for url in urls.into_iter().take(20) {
                if !Self::is_documentation_url(&url) {
                    results.api_endpoints.insert(url.clone());

                    // Check for GraphQL
                    if url.to_lowercase().contains("graphql") {
                        results.graphql_endpoints.insert(url);
                    }
                }
            }
        }

        // Extract GraphQL endpoints specifically
        if let Some(gql_endpoints) = self.scan_pattern(content, r#"['"`]((?:https?://)?[^'"`\s]*graphql[^'"`\s]*)['"`]"#, "GraphQL") {
            for endpoint in gql_endpoints.into_iter().take(10) {
                let clean = endpoint.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                results.graphql_endpoints.insert(clean.to_string());
            }
        }

        // Extract form action URLs
        if let Some(actions) = self.scan_pattern(content, r#"(?:action|formAction|submitUrl|postUrl|endpoint)\s*[=:]\s*['"`](/[^'"`]+|https?://[^'"`]+)['"`]"#, "Form Action") {
            for action in actions.into_iter().take(20) {
                let clean = action.split(&['=', ':'][..]).last().unwrap_or(&action)
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ' ');
                if !clean.contains("consent") && !clean.contains("cookie") {
                    results.form_actions.insert(clean.to_string());
                }
            }
        }

        // Extract query/body parameters from fetch/axios calls
        // Pattern: { param1: value, param2: value } or ?param1=&param2=
        self.extract_request_params(content, results);

        // Extract form field names
        if let Some(fields) = self.scan_pattern(content, r#"(?:name|field|param)\s*[=:]\s*['"`]([a-zA-Z_][a-zA-Z0-9_]{1,30})['"`]"#, "Field Name") {
            for field in fields.into_iter().take(50) {
                let clean = field.split(&['=', ':'][..]).last().unwrap_or(&field)
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ' ');
                if clean.len() > 1 && clean.len() < 30 {
                    // Add to a generic endpoint
                    results.parameters.entry("*".to_string())
                        .or_insert_with(HashSet::new)
                        .insert(clean.to_string());
                }
            }
        }

        // Extract React/Vue form input names
        if let Some(inputs) = self.scan_pattern(content, r#"(?:v-model|formik|register|Controller.*name)\s*[=:({]\s*['"`]?([a-zA-Z_][a-zA-Z0-9_]{1,30})['"`]?"#, "Form Input") {
            for input in inputs.into_iter().take(30) {
                let clean = input.split(&['=', ':', '(', '{'][..]).last().unwrap_or(&input)
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ' ' || c == ')' || c == '}');
                if clean.len() > 1 && clean.len() < 30 && !clean.contains("Controller") {
                    results.parameters.entry("*".to_string())
                        .or_insert_with(HashSet::new)
                        .insert(clean.to_string());
                }
            }
        }
    }

    /// Extract path parameters from URL patterns
    fn extract_path_params(&self, path: &str, results: &mut JsMinerResults) {
        // Match :param or {param} patterns
        let param_regex = Regex::new(r"[:/]\{?:?([a-zA-Z_][a-zA-Z0-9_]*)\}?").unwrap();
        for cap in param_regex.captures_iter(path) {
            if let Some(param) = cap.get(1) {
                let param_name = param.as_str();
                if param_name != "api" && param_name != "v1" && param_name != "v2" && param_name.len() > 1 {
                    results.parameters.entry(path.to_string())
                        .or_insert_with(HashSet::new)
                        .insert(param_name.to_string());
                }
            }
        }
    }

    /// Extract request parameters from fetch/axios/$.ajax calls
    fn extract_request_params(&self, content: &str, results: &mut JsMinerResults) {
        // Pattern for object properties: { key: value } in request bodies
        let obj_regex = Regex::new(r#"(?:body|data|params|query)\s*[=:]\s*\{([^}]{5,500})\}"#).unwrap();
        let key_regex = Regex::new(r#"['"]?([a-zA-Z_][a-zA-Z0-9_]{1,30})['"]?\s*:"#).unwrap();

        for cap in obj_regex.captures_iter(content) {
            if let Some(obj_content) = cap.get(1) {
                for key_cap in key_regex.captures_iter(obj_content.as_str()) {
                    if let Some(key) = key_cap.get(1) {
                        let param = key.as_str();
                        if param.len() > 1 && param.len() < 30 {
                            results.parameters.entry("*".to_string())
                                .or_insert_with(HashSet::new)
                                .insert(param.to_string());
                        }
                    }
                }
            }
        }

        // Pattern for URL query strings: ?param1=value&param2=value
        let qs_regex = Regex::new(r#"\?([a-zA-Z_][a-zA-Z0-9_]*=[^&\s'"]*(?:&[a-zA-Z_][a-zA-Z0-9_]*=[^&\s'"]*)*)"#).unwrap();
        let param_regex = Regex::new(r"([a-zA-Z_][a-zA-Z0-9_]*)=").unwrap();

        for cap in qs_regex.captures_iter(content) {
            if let Some(qs) = cap.get(1) {
                for param_cap in param_regex.captures_iter(qs.as_str()) {
                    if let Some(param) = param_cap.get(1) {
                        let param_name = param.as_str();
                        if param_name.len() > 1 && param_name.len() < 30 {
                            results.parameters.entry("*".to_string())
                                .or_insert_with(HashSet::new)
                                .insert(param_name.to_string());
                        }
                    }
                }
            }
        }
    }

    /// Analyze a JavaScript file
    async fn analyze_js_file(&self, js_url: &str, analyzed_urls: &mut HashSet<String>, vulnerabilities: &mut Vec<Vulnerability>, seen_evidence: &mut HashSet<String>) -> usize {
        if analyzed_urls.contains(js_url) {
            return 0;
        }

        analyzed_urls.insert(js_url.to_string());

        match self.http_client.get(js_url).await {
            Ok(response) => {
                // Only analyze if content type is JavaScript
                let content_type = response.headers.get("content-type")
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();

                if content_type.contains("javascript") || content_type.contains("application/json") || response.body.len() > 0 {
                    // Limit file size to 30MB
                    if response.body.len() <= 30 * 1024 * 1024 {
                        let before_count = vulnerabilities.len();
                        self.analyze_js_content(&response.body, js_url, vulnerabilities, seen_evidence);
                        let found = vulnerabilities.len() - before_count;
                        if found > 0 {
                            info!("[JS-Miner] Found {} issues in {}", found, js_url);
                        }
                        return 1;
                    }
                }
            }
            Err(e) => {
                info!("Failed to fetch JS file {}: {}", js_url, e);
            }
        }

        0
    }

    /// Add vulnerability only if evidence hasn't been seen before
    fn add_unique_vuln(&self, vulnerabilities: &mut Vec<Vulnerability>, seen: &mut HashSet<String>, vuln: Vulnerability) {
        let key = format!("{}:{}", vuln.vuln_type, vuln.evidence.as_ref().unwrap_or(&"".to_string()));
        if seen.insert(key) {
            vulnerabilities.push(vuln);
        }
    }

    /// Analyze JavaScript content for sensitive data
    fn analyze_js_content(&self, content: &str, location: &str, vulnerabilities: &mut Vec<Vulnerability>, seen_evidence: &mut HashSet<String>) {
        // AWS Keys
        if let Some(findings) = self.scan_pattern(content, r"AKIA[0-9A-Z]{16}", "AWS Access Key") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "AWS Access Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate AWS credentials immediately. Use environment variables or AWS IAM roles instead of hardcoding keys.",
                ));
            }
        }

        // Google API Keys
        if let Some(findings) = self.scan_pattern(content, r"AIza[0-9A-Za-z\-_]{35}", "Google API Key") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Google API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Google API key and implement API key restrictions (IP, referrer, API limits).",
                ));
            }
        }

        // Slack Tokens
        if let Some(findings) = self.scan_pattern(content, r"xox[baprs]-([0-9a-zA-Z]{10,48})", "Slack Token") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Slack Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Revoke Slack token immediately and rotate credentials. Use environment variables.",
                ));
            }
        }

        // Stripe Secret Keys
        if let Some(findings) = self.scan_pattern(content, r"sk_live_[0-9a-zA-Z]{24}", "Stripe Key") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Stripe Secret Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate Stripe secret key immediately. Use server-side only, never expose in client-side code.",
                ));
            }
        }

        // JWT Tokens
        if let Some(findings) = self.scan_pattern(content, r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*", "JWT Token") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "JWT Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Remove hardcoded JWT tokens. Implement secure token storage and rotation.",
                ));
            }
        }

        // Private Keys
        if let Some(findings) = self.scan_pattern(content, r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Private Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Remove private key from code immediately. Regenerate key pair if compromised. Use secure key storage.",
                ));
            }
        }

        // Database Connection Strings
        if let Some(findings) = self.scan_pattern(content, r#"(mongodb|mysql|postgres|redis)://[^\s"']+""#, "Database Connection") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Database Connection String Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Remove database credentials from client-side code. Use environment variables server-side only.",
                ));
            }
        }

        // API Endpoints (informational)
        if let Some(findings) = self.scan_pattern(content, r#"['"`](/api/[^'"`\s]+)['"`]"#, "API Endpoint") {
            for evidence in findings.into_iter().take(5) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "API Endpoint Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Ensure all API endpoints implement proper authentication and authorization.",
                ));
            }
        }

        // S3 Buckets
        if let Some(findings) = self.scan_pattern(content, r"https?://[a-zA-Z0-9.\-]+\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com", "S3 Bucket") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "S3 Bucket URL Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-200",
                    "Verify S3 bucket permissions. Ensure buckets are not publicly accessible unless intended.",
                ));
            }
        }

        // Bearer Tokens
        if let Some(findings) = self.scan_pattern(content, r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer Token") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Bearer Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Remove hardcoded bearer tokens. Implement secure token storage and rotation.",
                ));
            }
        }

        // API Keys (generic)
        if let Some(findings) = self.scan_pattern(content, r#"(?i)api[_-]?key["']?\s*[:=]\s*["']([^"']{16,})["']"#, "API Key") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Move API keys to environment variables or secure vault. Rotate exposed keys.",
                ));
            }
        }

        // Secrets (generic)
        if let Some(findings) = self.scan_pattern(content, r#"(?i)secret["']?\s*[:=]\s*["']([^"']{8,})["']"#, "Secret") {
            for evidence in findings.into_iter().take(3) {
                // Skip SDP/WebRTC parsing code and string concatenation patterns
                let is_false_positive = evidence.contains("+t.") ||
                    evidence.contains("+r.") ||
                    evidence.contains("+e.") ||
                    evidence.contains("+n.") ||
                    evidence.contains("+i.") ||
                    evidence.contains(r#"+""#) ||  // String concatenation
                    evidence.contains(".pass") ||
                    evidence.contains(".secret") ||
                    evidence.ends_with("+") ||
                    evidence.starts_with("+");

                if !is_false_positive {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "Secret Value Exposed",
                        location,
                        &evidence,
                        Severity::Medium,
                        "CWE-312",
                        "Remove hardcoded secrets from client-side code. Use server-side environment variables.",
                    ));
                }
            }
        }

        // Source Maps
        if content.contains("sourceMappingURL") {
            self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                "Source Map Exposed",
                location,
                "Source map reference found in production code",
                Severity::Medium,
                "CWE-540",
                "Remove source maps from production builds. They expose original source code structure.",
            ));
        }

        // Debug Mode
        if Regex::new(r"(?i)debug\s*[:=]\s*true").unwrap().is_match(content) {
            self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                "Debug Mode Enabled",
                location,
                "debug: true found in JavaScript",
                Severity::Low,
                "CWE-489",
                "Disable debug mode in production builds to prevent information disclosure.",
            ));
        }

        // Environment Variables
        if let Some(findings) = self.scan_pattern(content, r"process\.env\.[A-Z_]+", "Environment Variable") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Environment Variable Reference",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Ensure environment variables don't contain sensitive data accessible client-side.",
                ));
            }
        }

        // GraphQL Queries/Mutations/Fragments - require actual GraphQL syntax
        // Must have either gql`/graphql` template, or query/mutation with { or ( following
        // Pattern 1: gql` or graphql` template literals
        if let Some(findings) = self.scan_pattern(content, r#"(?:gql|graphql)\s*`[^`]*(?:query|mutation|subscription|fragment)\s+[A-Za-z_][A-Za-z0-9_]*"#, "GraphQL Operation") {
            for evidence in findings.into_iter().take(5) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GraphQL Operation Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "GraphQL operations expose API schema. Ensure proper authorization on all queries/mutations.",
                ));
            }
        }

        // Pattern 2: Standalone GraphQL operations with typical syntax (query Name { or mutation Name(
        if let Some(findings) = self.scan_pattern(content, r#"(?:query|mutation|subscription)\s+[A-Za-z_][A-Za-z0-9_]*\s*[\(\{]"#, "GraphQL Operation") {
            for evidence in findings.into_iter().take(5) {
                // Skip common false positives
                if !evidence.contains("querySelector") && !evidence.contains("querystring") {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "GraphQL Operation Discovered",
                        location,
                        &evidence,
                        Severity::Info,
                        "CWE-200",
                        "GraphQL operations expose API schema. Ensure proper authorization on all queries/mutations.",
                    ));
                }
            }
        }

        // GraphQL Endpoint URLs (handles various formats)
        if let Some(findings) = self.scan_pattern(content, r#"https?://[a-zA-Z0-9.\-]+[:/][^\s"'<>]*graphql"#, "GraphQL Endpoint") {
            for evidence in findings.into_iter().take(3) {
                // Skip documentation URLs (e.g., github.com/apollographql, docs.graphql.org)
                if Self::is_documentation_url(&evidence) {
                    continue;
                }
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GraphQL Endpoint Discovered",
                    location,
                    &evidence,
                    Severity::Low,
                    "CWE-200",
                    "GraphQL endpoint found. Ensure introspection is disabled in production and proper authentication is enforced.",
                ));
            }
        }

        // Sentry DSN (error tracking service credentials - case insensitive)
        if let Some(findings) = self.scan_pattern(content, r"https://[a-fA-F0-9]+@[a-zA-Z0-9]+\.ingest\.sentry\.io/[0-9]+", "Sentry DSN") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Sentry DSN Exposed",
                    location,
                    &evidence,
                    Severity::Low,
                    "CWE-200",
                    "Sentry DSN exposed. While public DSNs are common, attackers could send fake errors to pollute your error tracking.",
                ));
            }
        }

        // External API URLs (any https URL to api.* or */api/ or */v[0-9]/)
        if let Some(findings) = self.scan_pattern(content, r#"https://[a-zA-Z0-9.\-]+\.[a-z]{2,}/[^\s"'<>]*"#, "External URL") {
            // Filter to only API-like URLs, skip documentation
            let api_findings: Vec<String> = findings.into_iter()
                .filter(|url| {
                    // Must look like an API URL
                    (url.contains("/api") || url.contains("/v1") || url.contains("/v2") ||
                     url.contains("/v3") || url.contains("graphql") || url.starts_with("https://api.")) &&
                    // Skip documentation URLs
                    !Self::is_documentation_url(url)
                })
                .take(5)
                .collect();

            for evidence in api_findings {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "API Base URL Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "API base URL discovered. Ensure all endpoints implement proper authentication and rate limiting.",
                ));
            }
        }

        // Firebase/Supabase Configuration
        if let Some(findings) = self.scan_pattern(content, r#"https://[a-zA-Z0-9\-]+\.(firebaseio\.com|supabase\.co)[^"'\s]*"#, "Firebase/Supabase URL") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Backend-as-a-Service URL Discovered",
                    location,
                    &evidence,
                    Severity::Low,
                    "CWE-200",
                    "Firebase/Supabase URL found. Ensure security rules are properly configured to prevent unauthorized access.",
                ));
            }
        }

        // Internal/Private Network URLs
        if let Some(findings) = self.scan_pattern(content, r#"https?://(localhost|127\.0\.0\.1|192\.168\.[0-9.]+|10\.[0-9.]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9.]+)(:[0-9]+)?[^"'\s]*"#, "Internal URL") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Internal Network URL Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-200",
                    "Internal/private network URL found in client-side code. This may leak infrastructure details.",
                ));
            }
        }

        // Login/Authentication endpoints in JS
        if let Some(findings) = self.scan_pattern(content, r#"["'](/(?:api/)?(?:auth|login|signin|signup|register|logout|session|oauth|token)[^"']*?)["']"#, "Auth Endpoint") {
            for evidence in findings.into_iter().take(5) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Authentication Endpoint Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Authentication endpoint found. Test for authentication bypass, credential stuffing, and brute force protection.",
                ));
            }
        }

        // Password/credential field names in JS (forms rendered client-side)
        // Require context like field definition (name:, type:, field:) or input element
        if let Some(findings) = self.scan_pattern(content, r#"(?:name|type|field|id)\s*[=:]\s*["'](password|passwd|pwd|secret|credential)["']"#, "Credential Field") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Credential Field Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Credential-related field found. Indicates authentication form - test for weak password policies and credential handling.",
                ));
            }
        }

        // Email/username field patterns
        if let Some(findings) = self.scan_pattern(content, r#"["'](email|e-mail|username|user_name|login|userid|user_id)["']\s*:"#, "User Field") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "User Input Field Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "User input field found. Test associated forms for injection vulnerabilities.",
                ));
            }
        }

        // Form action URLs in JS - must be actual URL paths
        if let Some(findings) = self.scan_pattern(content, r#"(?:action|formAction|submitUrl|postUrl)\s*[=:]\s*["'](/[^"']+|https?://[^"']+)["']"#, "Form Action") {
            for evidence in findings.into_iter().take(5) {
                // Skip common false positives from consent/tracking scripts
                if !evidence.contains("consent") && !evidence.contains("cookie") &&
                   !evidence.contains("tracking") && !evidence.contains("analytics") {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "Form Action URL Discovered",
                        location,
                        &evidence,
                        Severity::Info,
                        "CWE-200",
                        "Form action URL found in JavaScript. Test endpoint for CSRF and input validation.",
                    ));
                }
            }
        }

        // Hardcoded credentials (critical)
        if let Some(findings) = self.scan_pattern(content, r#"(?:password|passwd|pwd|secret)\s*[=:]\s*["']([^"']{4,})["']"#, "Hardcoded Credential") {
            for evidence in findings.into_iter().take(3) {
                // Skip common false positives:
                // - placeholder/example values
                // - WebRTC/SDP parsing code (contains string concatenation like "+t.", "+r.", etc.)
                // - Variable references (contains just variable name patterns)
                let is_false_positive = evidence.contains("placeholder") ||
                    evidence.contains("example") ||
                    evidence.contains("****") ||
                    evidence.contains("+t.") ||
                    evidence.contains("+r.") ||
                    evidence.contains("+e.") ||
                    evidence.contains("+n.") ||
                    evidence.contains("+i.") ||
                    evidence.contains(r#"+""#) ||  // String concatenation
                    evidence.contains(r#""+}"#) || // End of concatenation
                    evidence.contains(".substr") ||
                    evidence.contains(".password") ||
                    evidence.contains(".passwd") ||
                    evidence.contains(".secret") ||
                    evidence.ends_with("+") ||
                    evidence.starts_with("+");

                if !is_false_positive {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "Potential Hardcoded Credential",
                        location,
                        &evidence,
                        Severity::High,
                        "CWE-798",
                        "Possible hardcoded credential found. Verify and remove any hardcoded secrets.",
                    ));
                }
            }
        }

        // ============================================
        // CLOUD PROVIDER CREDENTIALS
        // ============================================

        // Azure Storage Account Key
        if let Some(findings) = self.scan_pattern(content, r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "Azure Storage Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Azure Storage Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate Azure Storage key immediately. Use Azure Key Vault or managed identities.",
                ));
            }
        }

        // Azure Connection String
        if let Some(findings) = self.scan_pattern(content, r"(?i)Server=tcp:[^;]+;.*Password=[^;]+", "Azure SQL Connection") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Azure SQL Connection String Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Remove Azure SQL connection string from client code. Use managed identities or Key Vault.",
                ));
            }
        }

        // GCP Service Account JSON (partial match)
        if let Some(findings) = self.scan_pattern(content, r#""type"\s*:\s*"service_account"[^}]*"private_key"#, "GCP Service Account") {
            for evidence in findings.into_iter().take(1) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GCP Service Account Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Remove GCP service account key immediately. Use workload identity or secret manager.",
                ));
            }
        }

        // DigitalOcean API Token
        if let Some(findings) = self.scan_pattern(content, r"dop_v1_[a-f0-9]{64}", "DigitalOcean Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "DigitalOcean API Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke DigitalOcean API token immediately and rotate.",
                ));
            }
        }

        // Heroku API Key
        if let Some(findings) = self.scan_pattern(content, r#"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9-]{36}"#, "Heroku API Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Heroku API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Heroku API key immediately.",
                ));
            }
        }

        // ============================================
        // COMMUNICATION SERVICES
        // ============================================

        // Twilio Account SID and Auth Token
        if let Some(findings) = self.scan_pattern(content, r"AC[a-f0-9]{32}", "Twilio Account SID") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Twilio Account SID Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-200",
                    "Twilio Account SID found. Check if Auth Token is also exposed.",
                ));
            }
        }

        if let Some(findings) = self.scan_pattern(content, r#"(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*['\"]?[a-f0-9]{32}"#, "Twilio Auth Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Twilio Auth Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate Twilio Auth Token immediately. Never expose in client-side code.",
                ));
            }
        }

        // SendGrid API Key
        if let Some(findings) = self.scan_pattern(content, r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "SendGrid API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate SendGrid API key. Attackers could send emails on your behalf.",
                ));
            }
        }

        // Mailgun API Key
        if let Some(findings) = self.scan_pattern(content, r"key-[a-f0-9]{32}", "Mailgun API Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Mailgun API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Mailgun API key immediately.",
                ));
            }
        }

        // Pusher Keys
        if let Some(findings) = self.scan_pattern(content, r#"(?i)pusher[_-]?(app[_-]?)?(key|secret)\s*[=:]\s*['\"]?[a-f0-9]{20}"#, "Pusher Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Pusher Credentials Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Pusher credentials found. Rotate if secret is exposed.",
                ));
            }
        }

        // ============================================
        // DEVELOPER TOOLS & PLATFORMS
        // ============================================

        // GitHub Personal Access Token
        if let Some(findings) = self.scan_pattern(content, r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GitHub Personal Access Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke GitHub PAT immediately. Attackers could access your repositories.",
                ));
            }
        }

        // GitHub OAuth Token
        if let Some(findings) = self.scan_pattern(content, r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GitHub OAuth Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "GitHub OAuth token exposed. Revoke and rotate.",
                ));
            }
        }

        // GitLab Personal Access Token
        if let Some(findings) = self.scan_pattern(content, r"glpat-[a-zA-Z0-9_-]{20}", "GitLab PAT") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "GitLab Personal Access Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke GitLab PAT immediately.",
                ));
            }
        }

        // npm Token
        if let Some(findings) = self.scan_pattern(content, r"npm_[a-zA-Z0-9]{36}", "npm Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "npm Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke npm token immediately. Attackers could publish malicious packages.",
                ));
            }
        }

        // Cloudflare API Token
        if let Some(findings) = self.scan_pattern(content, r#"(?i)cloudflare[_-]?api[_-]?(key|token)\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{37,}"#, "Cloudflare Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Cloudflare API Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Cloudflare API token. Attackers could modify DNS/firewall rules.",
                ));
            }
        }

        // ============================================
        // OTHER SERVICES
        // ============================================

        // Algolia API Key
        if let Some(findings) = self.scan_pattern(content, r#"(?i)algolia[_-]?(api[_-]?)?(key|secret)\s*[=:]\s*['\"]?[a-f0-9]{32}"#, "Algolia Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Algolia API Key Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Algolia key found. Admin API key should never be in client code.",
                ));
            }
        }

        // MapBox Public Token
        if let Some(findings) = self.scan_pattern(content, r"pk\.[a-zA-Z0-9]{60,}", "MapBox Public Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "MapBox Public Token Exposed",
                    location,
                    &evidence,
                    Severity::Low,
                    "CWE-200",
                    "MapBox public token found. Ensure URL restrictions are configured.",
                ));
            }
        }

        // MapBox Secret Token
        if let Some(findings) = self.scan_pattern(content, r"sk\.[a-zA-Z0-9]{60,}", "MapBox Secret Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "MapBox Secret Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "MapBox secret token exposed. Rotate immediately - never use in client code.",
                ));
            }
        }

        // OpenAI API Key
        if let Some(findings) = self.scan_pattern(content, r"sk-[a-zA-Z0-9]{48}", "OpenAI Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "OpenAI API Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate OpenAI API key immediately. Attackers could use your API credits.",
                ));
            }
        }

        // Anthropic API Key
        if let Some(findings) = self.scan_pattern(content, r"sk-ant-[a-zA-Z0-9_-]{40,}", "Anthropic Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Anthropic API Key Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate Anthropic API key immediately.",
                ));
            }
        }

        // Hugging Face Token
        if let Some(findings) = self.scan_pattern(content, r"hf_[a-zA-Z0-9]{34}", "HuggingFace Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Hugging Face Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Revoke Hugging Face token. Attackers could access your models/datasets.",
                ));
            }
        }

        // Vercel Token
        if let Some(findings) = self.scan_pattern(content, r#"(?i)vercel[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9]{24}"#, "Vercel Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Vercel Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Vercel token. Attackers could deploy to your projects.",
                ));
            }
        }

        // Netlify Token
        if let Some(findings) = self.scan_pattern(content, r#"(?i)netlify[_-]?(auth[_-]?)?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{40,}"#, "Netlify Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Netlify Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Netlify token. Attackers could deploy to your sites.",
                ));
            }
        }

        // Datadog API Key
        if let Some(findings) = self.scan_pattern(content, r#"(?i)datadog[_-]?(api[_-]?)?key\s*[=:]\s*['\"]?[a-f0-9]{32}"#, "Datadog Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Datadog API Key Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Datadog API key found. Rotate if it's the application key.",
                ));
            }
        }

        // New Relic Key
        if let Some(findings) = self.scan_pattern(content, r"NRAK-[A-Z0-9]{27}", "New Relic Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "New Relic API Key Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Rotate New Relic API key.",
                ));
            }
        }

        // CircleCI Token
        if let Some(findings) = self.scan_pattern(content, r#"(?i)circle[_-]?ci[_-]?token\s*[=:]\s*['\"]?[a-f0-9]{40}"#, "CircleCI Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "CircleCI Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Revoke CircleCI token. Attackers could access your CI/CD pipelines.",
                ));
            }
        }

        // Linear API Key
        if let Some(findings) = self.scan_pattern(content, r"lin_api_[a-zA-Z0-9]{40}", "Linear API Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Linear API Key Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Revoke Linear API key.",
                ));
            }
        }

        // Notion API Key
        if let Some(findings) = self.scan_pattern(content, r"secret_[a-zA-Z0-9]{43}", "Notion Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Notion API Key Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-312",
                    "Revoke Notion API key. Attackers could access your workspace.",
                ));
            }
        }

        // Airtable API Key
        if let Some(findings) = self.scan_pattern(content, r"key[a-zA-Z0-9]{14}", "Airtable Key") {
            for evidence in findings.into_iter().take(2) {
                // Additional check - must be in context
                if evidence.len() == 17 {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "Potential Airtable API Key",
                        location,
                        &evidence,
                        Severity::Medium,
                        "CWE-312",
                        "Possible Airtable API key. Verify and rotate if confirmed.",
                    ));
                }
            }
        }

        // Auth0 Credentials
        if let Some(findings) = self.scan_pattern(content, r#"(?i)auth0[_-]?(client[_-]?)?(secret|key)\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}"#, "Auth0 Secret") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Auth0 Credentials Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Auth0 credentials exposed. Rotate client secret immediately.",
                ));
            }
        }

        // Okta API Token - require context to reduce false positives
        // The pattern 00[a-zA-Z0-9_-]{40} is too broad without context
        if content.to_lowercase().contains("okta") {
            if let Some(findings) = self.scan_pattern(content, r"00[a-zA-Z0-9_-]{40}", "Okta Token") {
                for evidence in findings.into_iter().take(2) {
                    // Skip if it looks like a hash or other hex string without okta context nearby
                    // Check if 'okta' appears within 100 chars of the match
                    let evidence_lower = evidence.to_lowercase();
                    let content_lower = content.to_lowercase();
                    if let Some(pos) = content_lower.find(&evidence_lower) {
                        let start = pos.saturating_sub(100);
                        let end = (pos + evidence.len() + 100).min(content_lower.len());
                        let context = &content_lower[start..end];
                        if context.contains("okta") {
                            self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                                "Potential Okta API Token",
                                location,
                                &evidence,
                                Severity::High,
                                "CWE-312",
                                "Possible Okta API token. Verify and revoke if confirmed.",
                            ));
                        }
                    }
                }
            }
        }

        // PyPI Token
        if let Some(findings) = self.scan_pattern(content, r"pypi-[a-zA-Z0-9_-]{100,}", "PyPI Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "PyPI Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke PyPI token immediately. Attackers could publish malicious packages.",
                ));
            }
        }

        // Docker Hub Token
        if let Some(findings) = self.scan_pattern(content, r"dckr_pat_[a-zA-Z0-9_-]{56}", "Docker Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Docker Hub Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke Docker Hub token. Attackers could push malicious images.",
                ));
            }
        }

        // Postmark Token
        if let Some(findings) = self.scan_pattern(content, r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "Postmark/UUID Token") {
            // This is UUID format - only flag if in postmark/email context
            for evidence in findings.into_iter().take(2) {
                if content.to_lowercase().contains("postmark") {
                    self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                        "Postmark API Token Exposed",
                        location,
                        &evidence,
                        Severity::High,
                        "CWE-312",
                        "Rotate Postmark API token. Attackers could send emails.",
                    ));
                }
            }
        }

        // Vonage/Nexmo Key
        if let Some(findings) = self.scan_pattern(content, r#"(?i)(vonage|nexmo)[_-]?(api[_-]?)?(key|secret)\s*[=:]\s*['\"]?[a-zA-Z0-9]{8,}"#, "Vonage Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Vonage/Nexmo Credentials Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Vonage/Nexmo credentials. Attackers could send SMS/calls.",
                ));
            }
        }

        // Plivo Credentials
        if let Some(findings) = self.scan_pattern(content, r#"(?i)plivo[_-]?(auth[_-]?)?(id|token)\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}"#, "Plivo Credential") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Plivo Credentials Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Plivo credentials. Attackers could make calls/send SMS.",
                ));
            }
        }

        // Telegram Bot Token
        if let Some(findings) = self.scan_pattern(content, r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "Telegram Bot Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Telegram Bot Token Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Revoke Telegram bot token via @BotFather immediately.",
                ));
            }
        }

        // Discord Webhook
        if let Some(findings) = self.scan_pattern(content, r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", "Discord Webhook") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Discord Webhook URL Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-200",
                    "Delete and recreate Discord webhook. Attackers could send messages to your channel.",
                ));
            }
        }

        // Discord Bot Token
        if let Some(findings) = self.scan_pattern(content, r"[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}", "Discord Bot Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Discord Bot Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Regenerate Discord bot token immediately via Developer Portal.",
                ));
            }
        }

        // Shopify API Key
        if let Some(findings) = self.scan_pattern(content, r"shpat_[a-fA-F0-9]{32}", "Shopify Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Shopify Access Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke Shopify access token. Attackers could access store data.",
                ));
            }
        }

        // Shopify Shared Secret
        if let Some(findings) = self.scan_pattern(content, r"shpss_[a-fA-F0-9]{32}", "Shopify Secret") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Shopify Shared Secret Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rotate Shopify shared secret immediately.",
                ));
            }
        }

        // Mailchimp API Key
        if let Some(findings) = self.scan_pattern(content, r"[a-f0-9]{32}-us[0-9]{1,2}", "Mailchimp Key") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Mailchimp API Key Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "Rotate Mailchimp API key. Attackers could access mailing lists.",
                ));
            }
        }

        // PayPal Client ID/Secret
        if let Some(findings) = self.scan_pattern(content, r#"(?i)paypal[_-]?(client[_-]?)?(id|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}"#, "PayPal Credential") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "PayPal Credentials Exposed",
                    location,
                    &evidence,
                    Severity::High,
                    "CWE-312",
                    "PayPal credentials found. Secret should never be in client code.",
                ));
            }
        }

        // Square Access Token
        if let Some(findings) = self.scan_pattern(content, r"sq0atp-[a-zA-Z0-9_-]{22}", "Square Token") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Square Access Token Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Revoke Square access token immediately.",
                ));
            }
        }

        // ============================================
        // FRAMEWORK SECRETS
        // ============================================

        // Laravel APP_KEY
        if let Some(findings) = self.scan_pattern(content, r"base64:[a-zA-Z0-9+/]{43}=", "Laravel APP_KEY") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Laravel APP_KEY Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Laravel APP_KEY exposed. Regenerate with 'php artisan key:generate'. All encrypted data is compromised.",
                ));
            }
        }

        // Django SECRET_KEY
        if let Some(findings) = self.scan_pattern(content, r#"(?i)django[_-]?secret[_-]?key\s*[=:]\s*["'][a-zA-Z0-9!@#$%^&*()_+-=]{50,}["']"#, "Django SECRET_KEY") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Django SECRET_KEY Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Django SECRET_KEY exposed. Sessions and signed data are compromised. Regenerate immediately.",
                ));
            }
        }

        // Rails secret_key_base
        if let Some(findings) = self.scan_pattern(content, r#"(?i)secret_key_base\s*[=:]\s*['\"]?[a-f0-9]{128}"#, "Rails Secret") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Rails secret_key_base Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-312",
                    "Rails secret_key_base exposed. Regenerate with 'rails secret'.",
                ));
            }
        }

        // ============================================
        // FINNISH PII (Personal Identifiable Information)
        // ============================================

        // Finnish HETU (Personal Identity Code) - Format: DDMMYY[-+A]XXXX
        // Day: 01-31, Month: 01-12, Year: 00-99, Century: - (+1900), + (+1800), A (+2000)
        // Last 4: 3 digits + check character
        if let Some(findings) = self.scan_pattern(content, r"(?:0[1-9]|[12][0-9]|3[01])(?:0[1-9]|1[0-2])[0-9]{2}[-+A][0-9]{3}[0-9A-Y]", "Finnish HETU") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Finnish Personal Identity Code (HETU) Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-359",
                    "Finnish HETU exposed - GDPR violation. Remove immediately and report data breach.",
                ));
            }
        }

        // Finnish Y-tunnus (Business ID) - Format: 1234567-8
        if let Some(findings) = self.scan_pattern(content, r"[0-9]{7}-[0-9]", "Finnish Y-tunnus") {
            for evidence in findings.into_iter().take(3) {
                // Skip placeholder/test values
                let placeholder_values = [
                    "0000000-0",
                    "1234567-8",
                    "1234567-1",
                    "0000000-1",
                    "9999999-9",
                ];
                if placeholder_values.contains(&evidence.as_str()) {
                    continue;
                }
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Finnish Business ID (Y-tunnus) Found",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Finnish Y-tunnus found. While public, verify it's intentionally exposed.",
                ));
            }
        }

        // Finnish IBAN
        if let Some(findings) = self.scan_pattern(content, r"FI[0-9]{2}\s?[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}\s?[0-9]{2}", "Finnish IBAN") {
            for evidence in findings.into_iter().take(3) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Finnish Bank Account (IBAN) Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-359",
                    "Finnish IBAN exposed. Review if this should be in client-side code.",
                ));
            }
        }

        // Finnish Verkkolaskuosoite (E-Invoice Address / OVT Identifier)
        // Format: 0037XXXXXXXXX (0037 = Finland country code + business ID without dash)
        // Total length: 12-17 digits
        if let Some(findings) = self.scan_pattern(content, r"0037[0-9]{8,13}", "Finnish OVT/Verkkolaskuosoite") {
            for evidence in findings.into_iter().take(3) {
                // Skip placeholder values
                let placeholder_values = [
                    "003700000000",
                    "003712345678",
                    "00371234567890",
                ];
                if placeholder_values.iter().any(|&p| evidence.contains(p)) {
                    continue;
                }
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Finnish E-Invoice Address (Verkkolaskuosoite) Found",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Finnish Verkkolaskuosoite/OVT identifier found. While often public, verify it's intentionally exposed.",
                ));
            }
        }

        // ============================================
        // OTHER PII
        // ============================================

        // Generic Credit Card Numbers (with Luhn validation and false positive filtering)
        if let Some(findings) = self.scan_pattern(content, r"(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})", "Credit Card") {
            for evidence in findings.into_iter().take(2) {
                // Filter known JavaScript numeric constants (powers of 2, MAX_SAFE_INTEGER related)
                let known_js_constants = [
                    "4503599627370496",  // 2^52
                    "4503599627370495",  // 2^52 - 1
                    "4611686018427387",  // Related to 2^62
                    "4801650304020105",  // Common minified code constant
                    "4294967296",        // 2^32 (though shorter)
                    "4398046511104",     // 2^42
                ];

                // Skip if it's a known JS constant
                if known_js_constants.iter().any(|&c| evidence.contains(c)) {
                    continue;
                }

                // Validate using Luhn algorithm
                if !Self::luhn_check(&evidence) {
                    continue;
                }

                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Potential Credit Card Number Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-311",
                    "Possible credit card number in code. PCI-DSS violation if confirmed.",
                ));
            }
        }

        // Social Security Number (US)
        if let Some(findings) = self.scan_pattern(content, r"[0-9]{3}-[0-9]{2}-[0-9]{4}", "US SSN") {
            for evidence in findings.into_iter().take(2) {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Potential US Social Security Number Exposed",
                    location,
                    &evidence,
                    Severity::Critical,
                    "CWE-359",
                    "Possible SSN in code. Remove immediately if confirmed.",
                ));
            }
        }

        // Email addresses in config (might indicate test/debug accounts)
        if let Some(findings) = self.scan_pattern(content, r#"["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["']"#, "Email") {
            // Only report if it looks like a config value
            let config_emails: Vec<String> = findings.into_iter()
                .filter(|e| e.contains("admin") || e.contains("test") || e.contains("debug") || e.contains("dev@"))
                .take(3)
                .collect();

            for evidence in config_emails {
                self.add_unique_vuln(vulnerabilities, seen_evidence, self.create_vulnerability(
                    "Debug/Admin Email Address Found",
                    location,
                    &evidence,
                    Severity::Low,
                    "CWE-200",
                    "Debug or admin email found. May indicate test configuration in production.",
                ));
            }
        }
    }

    /// Luhn algorithm check for credit card validation
    fn luhn_check(number: &str) -> bool {
        let digits: Vec<u32> = number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut double = false;

        for &digit in digits.iter().rev() {
            let mut d = digit;
            if double {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
            double = !double;
        }

        sum % 10 == 0
    }

    /// Scan content for regex pattern and return unique matches
    fn scan_pattern(&self, content: &str, pattern: &str, _name: &str) -> Option<Vec<String>> {
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let matches: Vec<String> = regex
            .find_iter(content)
            .map(|m| {
                let matched = m.as_str();
                // Truncate very long matches
                if matched.len() > 100 {
                    format!("{}...", &matched[..100])
                } else {
                    matched.to_string()
                }
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        remediation: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("jsminer_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "JavaScript Analysis".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> JsMinerScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        JsMinerScanner::new(client)
    }

    #[test]
    fn test_scan_pattern_aws_key() {
        let scanner = create_test_scanner();

        let content = "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';";
        let findings = scanner.scan_pattern(content, r"AKIA[0-9A-Z]{16}", "AWS Key");

        assert!(findings.is_some());
        let matches = findings.unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_scan_pattern_jwt() {
        let scanner = create_test_scanner();

        let content = "token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'";
        let findings = scanner.scan_pattern(content, r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*", "JWT");

        assert!(findings.is_some());
    }

    #[test]
    fn test_discover_js_files() {
        let scanner = create_test_scanner();

        let html = r#"<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>"#;
        let files = scanner.discover_js_files("https://example.com", html);

        assert!(files.len() >= 2);
        assert!(files.iter().any(|f| f.contains("app.js")));
    }

    #[test]
    fn test_detect_source_map() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = "//# sourceMappingURL=app.js.map";
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Source Map")));
    }

    #[test]
    fn test_detect_debug_mode() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = "const config = { debug: true, api: 'https://api.example.com' };";
        scanner.analyze_js_content(content, "https://example.com/config.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Debug Mode")));
    }

    #[test]
    fn test_detect_graphql_operations() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = r#"
            const GET_USER = gql`
                query GetUser($id: ID!) {
                    user(id: $id) {
                        name
                        email
                    }
                }
            `;
            const CREATE_POST = gql`
                mutation CreatePost($input: PostInput!) {
                    createPost(input: $input) {
                        id
                    }
                }
            `;
            const USER_FIELDS = gql`
                fragment UserFields on User {
                    id
                    name
                }
            `;
        "#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("GraphQL Operation")));
    }

    #[test]
    fn test_detect_graphql_endpoint() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = r#"const API_URL = "https://api.example.com/graphql";"#;
        scanner.analyze_js_content(content, "https://example.com/config.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("GraphQL Endpoint")));
    }

    #[test]
    fn test_detect_sentry_dsn() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = r#"Sentry.init({ dsn: "https://c016413d689e4e26a8a84f5b094e3b78@o559839.ingest.sentry.io/5984200" });"#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Sentry DSN")));
    }

    #[test]
    fn test_detect_api_base_url() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = r#"fetch("https://backend.example.com/api/users")"#;
        scanner.analyze_js_content(content, "https://example.com/config.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("API Base URL")));
    }

    #[test]
    fn test_detect_internal_url() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();

        let content = r#"const devApi = "http://192.168.1.100:3000/api";"#;
        scanner.analyze_js_content(content, "https://example.com/config.js", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Internal Network URL")));
    }

    // ============================================
    // FALSE POSITIVE FILTERING TESTS
    // ============================================

    #[test]
    fn test_luhn_check_valid_card() {
        // Visa test card number (passes Luhn)
        assert!(JsMinerScanner::luhn_check("4111111111111111"));
        // MasterCard test card number (passes Luhn)
        assert!(JsMinerScanner::luhn_check("5500000000000004"));
    }

    #[test]
    fn test_luhn_check_invalid_numbers() {
        // JavaScript constants that match CC regex but fail Luhn
        assert!(!JsMinerScanner::luhn_check("4503599627370496")); // 2^52
        assert!(!JsMinerScanner::luhn_check("4801650304020105")); // Minified code constant
    }

    #[test]
    fn test_no_credit_card_for_js_constants() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // Content with JavaScript numeric constants that look like credit cards
        let content = r#"var MAX_VALUE = 4503599627370496; var OTHER = 4801650304020105;"#;
        scanner.analyze_js_content(content, "https://example.com/math.js", &mut vulns, &mut seen);

        // Should NOT detect these as credit cards
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("Credit Card")));
    }

    #[test]
    fn test_no_okta_token_without_context() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // Hex string that matches Okta pattern but without okta context
        let content = r#"var hash = "0000738c9e0c40b8dcdfd5468754b6405540157e01";"#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns, &mut seen);

        // Should NOT detect as Okta token
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("Okta")));
    }

    #[test]
    fn test_no_credential_for_sdp_parsing() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // WebRTC SDP parsing code
        let content = r#"var sdp = "pwd:"+t.password+""; var ice = "secret="+r.pass;"#;
        scanner.analyze_js_content(content, "https://example.com/webrtc.js", &mut vulns, &mut seen);

        // Should NOT detect as hardcoded credential
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("Hardcoded Credential")));
    }

    #[test]
    fn test_no_graphql_endpoint_for_github_urls() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // GitHub URL to apollographql
        let content = r#"// See https://github.com/apollographql/apollo-client for docs"#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns, &mut seen);

        // Should NOT detect GitHub URL as GraphQL endpoint
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("GraphQL Endpoint") &&
                                      v.evidence.as_ref().map(|e| e.contains("github.com")).unwrap_or(false)));
    }

    #[test]
    fn test_no_ytunnus_for_placeholder() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // Placeholder Y-tunnus
        let content = r#"const PLACEHOLDER_YTUNNUS = "0000000-0";"#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns, &mut seen);

        // Should NOT detect placeholder as Y-tunnus
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("Y-tunnus")));
    }

    #[test]
    fn test_detect_verkkolaskuosoite() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // Real-looking Finnish e-invoice address
        let content = r#"const OVT = "003726994471";"#;
        scanner.analyze_js_content(content, "https://example.com/invoice.js", &mut vulns, &mut seen);

        // Should detect as Verkkolaskuosoite
        assert!(vulns.iter().any(|v| v.vuln_type.contains("E-Invoice Address") ||
                                     v.vuln_type.contains("Verkkolaskuosoite")));
    }

    #[test]
    fn test_no_verkkolaskuosoite_for_placeholder() {
        let scanner = create_test_scanner();
        let mut vulns = Vec::new();
        let mut seen = HashSet::new();

        // Placeholder OVT
        let content = r#"const PLACEHOLDER = "003700000000";"#;
        scanner.analyze_js_content(content, "https://example.com/app.js", &mut vulns, &mut seen);

        // Should NOT detect placeholder
        assert!(!vulns.iter().any(|v| v.vuln_type.contains("Verkkolaskuosoite")));
    }
}
