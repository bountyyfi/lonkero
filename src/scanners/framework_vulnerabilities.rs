// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

/// Snap a byte index down to the nearest valid UTF-8 char boundary.
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Snap a byte index up to the nearest valid UTF-8 char boundary.
fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for framework-specific vulnerabilities
pub struct FrameworkVulnerabilitiesScanner {
    http_client: Arc<HttpClient>,
}

impl FrameworkVulnerabilitiesScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Run framework vulnerability scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting framework vulnerability scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Get initial response to detect framework
        let initial_response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(_) => return Ok((all_vulnerabilities, 0)),
        };

        let html = &initial_response.body;

        // Test Next.js
        let (vulns, tests) = self.scan_nextjs(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test React
        let (vulns, tests) = self.scan_react(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Vue
        let (vulns, tests) = self.scan_vue(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Angular
        let (vulns, tests) = self.scan_angular(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Django
        let (vulns, tests) = self.scan_django(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Laravel
        let (vulns, tests) = self.scan_laravel(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test WordPress
        let (vulns, tests) = self.scan_wordpress(url, html).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Spring Boot (Actuator) — runs regardless of indicators in HTML
        // because the landing page often hides Spring Boot, but actuator endpoints
        // are extremely high-value when exposed.
        let (vulns, tests) = self.scan_spring_boot_actuator(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "Framework vulnerability scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Scan Next.js specific vulnerabilities
    async fn scan_nextjs(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        // Check if Next.js
        if !html.contains("__NEXT_DATA__") && !html.contains("/_next/") {
            return Ok((vulnerabilities, 0));
        }

        info!("Next.js detected, running framework-specific tests");

        // Test 1: Sensitive data in __NEXT_DATA__
        if let Some(next_data) = self.extract_next_data(html) {
            if next_data.to_lowercase().contains("password")
                || next_data.to_lowercase().contains("secret")
                || next_data.to_lowercase().contains("api_key")
                || next_data.to_lowercase().contains("token")
            {
                vulnerabilities.push(self.create_vulnerability(
                    "Next.js Sensitive Data Exposure",
                    url,
                    "Sensitive data exposed in __NEXT_DATA__ object",
                    Severity::High,
                    "CWE-200",
                ));
            }
        }

        // Test 2: API routes enumeration
        let api_routes = vec![
            "/api/auth",
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/debug",
        ];

        for route in api_routes {
            let api_url = format!("{}{}", url.trim_end_matches('/'), route);
            if let Ok(response) = self.http_client.get(&api_url).await {
                if response.status_code == 200 && !response.body.contains("Not Found") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Next.js API Route Exposed",
                        &api_url,
                        &format!("Accessible API route without authentication: {}", route),
                        Severity::Medium,
                        "CWE-306",
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan React specific vulnerabilities
    async fn scan_react(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        // Check for SPECIFIC React indicators, not just the word "react"
        // Note: Don't run if already detected Next.js (which is React-based)
        let has_react_root = html.contains("data-reactroot") || html.contains("data-react-");
        let has_react_bundle = html.contains("/react.") || html.contains("/react-dom.");
        let has_react_devtools = html.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__");

        if !has_react_root && !has_react_bundle && !has_react_devtools {
            return Ok((vulnerabilities, 0));
        }

        info!("React detected, running framework-specific tests");

        // Test: dangerouslySetInnerHTML usage
        if html.contains("dangerouslySetInnerHTML") {
            vulnerabilities.push(self.create_vulnerability(
                "React dangerouslySetInnerHTML Usage",
                url,
                "Use of dangerouslySetInnerHTML detected, potential XSS risk",
                Severity::Medium,
                "CWE-79",
            ));
        }

        // Test: React DevTools in production
        if html.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__") {
            vulnerabilities.push(self.create_vulnerability(
                "React DevTools Enabled in Production",
                url,
                "React DevTools detected in production build",
                Severity::Low,
                "CWE-489",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan Vue specific vulnerabilities
    async fn scan_vue(&self, url: &str, html: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        // Check for SPECIFIC Vue indicators
        // Must have Vue-specific patterns, not just "v-" (which could be any attribute)
        let has_vue_app = html.contains("data-v-") || html.contains("[data-v-");
        let has_vue_bundle =
            html.contains("/vue.") || html.contains("/vue@") || html.contains("vue.runtime");
        let has_vue_devtools = html.contains("__VUE_DEVTOOLS_GLOBAL_HOOK__");
        let has_vue_specific =
            html.contains("v-cloak") || html.contains("v-model") || html.contains("v-bind");

        if !has_vue_app && !has_vue_bundle && !has_vue_devtools && !has_vue_specific {
            return Ok((vulnerabilities, 0));
        }

        info!("Vue.js detected, running framework-specific tests");

        // Test: v-html usage (XSS risk)
        if html.contains("v-html") {
            vulnerabilities.push(self.create_vulnerability(
                "Vue v-html Usage Detected",
                url,
                "Use of v-html directive detected, potential XSS risk",
                Severity::Medium,
                "CWE-79",
            ));
        }

        // Test: Vue DevTools in production
        if html.contains("__VUE_DEVTOOLS_GLOBAL_HOOK__") {
            vulnerabilities.push(self.create_vulnerability(
                "Vue DevTools Enabled in Production",
                url,
                "Vue DevTools detected in production build",
                Severity::Low,
                "CWE-489",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan Angular specific vulnerabilities
    async fn scan_angular(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        // Check for SPECIFIC Angular indicators
        // Must have Angular-specific patterns, not just "ng-" (which could be other things)
        let has_ng_app = html.contains("ng-app=") || html.contains("ng-controller=");
        let has_angular_bundle = html.contains("/angular.")
            || html.contains("angular.min.js")
            || html.contains("@angular/");
        let has_ng_version = html.contains("ng-version=");
        let has_ng_csp = html.contains("ng-csp") || html.contains("ng-strict-di");

        if !has_ng_app && !has_angular_bundle && !has_ng_version && !has_ng_csp {
            return Ok((vulnerabilities, 0));
        }

        info!("Angular detected, running framework-specific tests");

        // Test: bypassSecurityTrust usage
        if html.contains("bypassSecurityTrust") {
            vulnerabilities.push(self.create_vulnerability(
                "Angular bypassSecurityTrust Usage",
                url,
                "Use of bypassSecurityTrust detected, potential XSS risk",
                Severity::Medium,
                "CWE-79",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan Django specific vulnerabilities
    async fn scan_django(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        // Check for SPECIFIC Django indicators - not just the word "django"
        // Many sites mention Django in comments or meta without actually using it
        let has_django_csrf = html.contains("csrfmiddlewaretoken");
        let has_django_debug = html.contains("Django Debug") || html.contains("django.setup");
        let has_django_admin = html.contains("/admin/login/") && html.contains("Django");
        let has_django_error = html.contains("django.core") || html.contains("django.db");

        if !has_django_csrf && !has_django_debug && !has_django_admin && !has_django_error {
            return Ok((vulnerabilities, 0));
        }

        info!("Django detected, running framework-specific tests");

        // Test: Debug mode enabled
        if html.contains("DEBUG = True") || html.contains("Django Debug") {
            vulnerabilities.push(self.create_vulnerability(
                "Django Debug Mode Enabled",
                url,
                "Django debug mode is enabled in production",
                Severity::High,
                "CWE-489",
            ));
        }

        // Test: Admin panel accessible
        let admin_url = format!("{}/admin/", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&admin_url).await {
            if response.status_code == 200 && response.body.contains("Django") {
                vulnerabilities.push(self.create_vulnerability(
                    "Django Admin Panel Exposed",
                    &admin_url,
                    "Django admin panel is publicly accessible",
                    Severity::Medium,
                    "CWE-548",
                ));
            }
        }

        // Test: django-silk profiler exposure — full request/SQL profiling UI
        let silk_url = format!("{}/silk/", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&silk_url).await {
            if response.status_code == 200
                && response.body.contains("silk")
                && (response.body.contains("Profiling")
                    || response.body.contains("silk-summary")
                    || response.body.contains("Silk &middot;"))
            {
                vulnerabilities.push(self.create_vulnerability(
                    "Django Silk Profiler Exposed",
                    &silk_url,
                    "django-silk profiler UI is publicly accessible — exposes recent requests, SQL queries with bound parameters, response bodies and timing",
                    Severity::High,
                    "CWE-489",
                ));
            }
        }

        // Test: django-debug-toolbar — confirmed via the static asset path it always serves
        let djdt_url = format!(
            "{}/__debug__/render_panel/",
            url.trim_end_matches('/')
        );
        if let Ok(response) = self.http_client.get(&djdt_url).await {
            if response.status_code == 200 || response.status_code == 400 {
                if response.body.contains("debug_toolbar")
                    || response.body.contains("djDebug")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "Django Debug Toolbar Enabled",
                        &djdt_url,
                        "django-debug-toolbar is exposed — leaks settings, SQL, templates, and request state",
                        Severity::High,
                        "CWE-489",
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan Laravel specific vulnerabilities
    async fn scan_laravel(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        // Check for SPECIFIC Laravel indicators - not just the word "laravel"
        // Must have Laravel-specific patterns in the HTML/response
        let has_laravel_csrf = html.contains("csrf_token()") || html.contains("X-CSRF-TOKEN");
        let has_laravel_errors = html.contains("Whoops!") && html.contains("Laravel");
        let has_laravel_session = html.contains("laravel_session");
        let has_laravel_specific =
            html.contains("Laravel Mix") || html.contains("@vite") && html.contains("resources/");

        if !has_laravel_csrf && !has_laravel_errors && !has_laravel_session && !has_laravel_specific
        {
            return Ok((vulnerabilities, 0));
        }

        info!("Laravel detected, running framework-specific tests");

        // Test: Laravel Telescope accessible
        let telescope_url = format!("{}/telescope", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&telescope_url).await {
            if response.status_code == 200 && response.body.contains("Telescope") {
                vulnerabilities.push(self.create_vulnerability(
                    "Laravel Telescope Exposed",
                    &telescope_url,
                    "Laravel Telescope debugging tool is publicly accessible",
                    Severity::High,
                    "CWE-489",
                ));
            }
        }

        // Test: Laravel Horizon (queue/worker dashboard — leaks job payloads, sometimes with PII)
        let horizon_url = format!("{}/horizon", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&horizon_url).await {
            if response.status_code == 200
                && (response.body.contains("Laravel Horizon")
                    || response.body.contains("horizon-app"))
            {
                vulnerabilities.push(self.create_vulnerability(
                    "Laravel Horizon Exposed",
                    &horizon_url,
                    "Laravel Horizon queue dashboard publicly accessible — exposes job payloads, failed jobs (often with PII), and worker config",
                    Severity::High,
                    "CWE-489",
                ));
            }
        }

        // Test: Laravel Debugbar — confirm via the asset that's always served when enabled
        let debugbar_url = format!("{}/_debugbar/open", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&debugbar_url).await {
            if response.status_code == 200 && response.body.contains("PHPDEBUGBAR_STACK_DATA") {
                vulnerabilities.push(self.create_vulnerability(
                    "Laravel Debugbar Enabled",
                    &debugbar_url,
                    "Laravel Debugbar is enabled — exposes SQL queries, route info, request/session data, and environment variables",
                    Severity::High,
                    "CWE-215",
                ));
            }
        }

        // Test: Ignition error page exposure (CVE-2021-3129 surface).
        // We don't exploit; we only flag if the Ignition execute-solution endpoint
        // responds with its characteristic JSON validation error.
        let ignition_url = format!("{}/_ignition/execute-solution", url.trim_end_matches('/'));
        if let Ok(response) = self
            .http_client
            .request_with_method("POST", &ignition_url)
            .await
        {
            // Ignition returns 422 with "solution" or "parameters" in the JSON body
            // when the route exists but the payload is missing.
            if (response.status_code == 422 || response.status_code == 400)
                && response.body.contains("solution")
                && (response.body.contains("parameters")
                    || response.body.contains("must be present"))
            {
                vulnerabilities.push(self.create_vulnerability(
                    "Laravel Ignition Endpoint Exposed",
                    &ignition_url,
                    "Ignition execute-solution endpoint is reachable. On vulnerable versions this leads to CVE-2021-3129 (unauth RCE). At minimum it exposes the debug error page with stack traces and environment.",
                    Severity::Critical,
                    "CWE-94",
                ));
            }
        }

        // Test: Laravel storage paths sometimes leaked via web root (storage/logs/laravel.log)
        let storage_log = format!(
            "{}/storage/logs/laravel.log",
            url.trim_end_matches('/')
        );
        if let Ok(response) = self.http_client.get(&storage_log).await {
            if response.status_code == 200
                // laravel.log lines always start with the bracketed RFC3339 timestamp
                // followed by env.LEVEL, e.g. "[2024-05-13 10:00:00] production.ERROR:"
                && regex::Regex::new(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+\.(ERROR|WARNING|INFO|DEBUG):")
                    .ok()
                    .map(|re| re.is_match(&response.body))
                    .unwrap_or(false)
            {
                vulnerabilities.push(self.create_vulnerability(
                    "Laravel storage/logs/laravel.log Exposed",
                    &storage_log,
                    "Application log file is publicly readable — exposes stack traces, SQL queries, user identifiers, and sometimes secrets logged in error paths",
                    Severity::High,
                    "CWE-532",
                ));
            }
        }

        // Test: Debug mode
        if html.contains("APP_DEBUG") || html.contains("Whoops") {
            vulnerabilities.push(self.create_vulnerability(
                "Laravel Debug Mode Enabled",
                url,
                "Laravel debug mode is enabled in production",
                Severity::High,
                "CWE-489",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan WordPress specific vulnerabilities
    async fn scan_wordpress(
        &self,
        url: &str,
        html: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        if !html.contains("wp-content") && !html.contains("wordpress") {
            return Ok((vulnerabilities, 0));
        }

        info!("WordPress detected, running framework-specific tests");

        // Test: Version detection
        if let Some(version) = self.extract_wordpress_version(html) {
            vulnerabilities.push(self.create_vulnerability(
                "WordPress Version Disclosure",
                url,
                &format!("WordPress version disclosed: {}", version),
                Severity::Low,
                "CWE-200",
            ));
        }

        // Test: xmlrpc.php enabled
        let xmlrpc_url = format!("{}/xmlrpc.php", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&xmlrpc_url).await {
            if response.status_code == 200 {
                vulnerabilities.push(self.create_vulnerability(
                    "WordPress xmlrpc.php Enabled",
                    &xmlrpc_url,
                    "xmlrpc.php is accessible, can be used for brute force and amplification attacks",
                    Severity::Medium,
                    "CWE-307",
                ));
            }
        }

        // Test: User enumeration
        let user_enum_url = format!("{}/?author=1", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&user_enum_url).await {
            if response.status_code == 200 && response.body.contains("author/") {
                vulnerabilities.push(self.create_vulnerability(
                    "WordPress User Enumeration",
                    &user_enum_url,
                    "WordPress allows user enumeration via author parameter",
                    Severity::Low,
                    "CWE-200",
                ));
            }
        }

        // Test: wp-content/debug.log exposure — WP_DEBUG_LOG can leak stack traces, DB queries, user info
        let debug_log_url = format!(
            "{}/wp-content/debug.log",
            url.trim_end_matches('/')
        );
        if let Ok(response) = self.http_client.get(&debug_log_url).await {
            if response.status_code == 200
                // WP debug.log lines are "[DD-MMM-YYYY HH:MM:SS UTC] PHP <Level>:" — very specific
                && regex::Regex::new(
                    r"\[\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2} [A-Z]{2,4}\] PHP",
                )
                .ok()
                .map(|re| re.is_match(&response.body))
                .unwrap_or(false)
            {
                vulnerabilities.push(self.create_vulnerability(
                    "WordPress wp-content/debug.log Exposed",
                    &debug_log_url,
                    "WordPress debug log is publicly readable — leaks PHP stack traces, plugin paths, SQL errors and sometimes secrets logged on failure",
                    Severity::High,
                    "CWE-532",
                ));
            }
        }

        // Test: wp-config backup variants — these expose DB credentials and auth keys
        let config_backup_paths = vec![
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/wp-config.php.save",
            "/wp-config.php.swp",
            "/wp-config.php.old",
            "/.wp-config.php.swp",
        ];
        for path in &config_backup_paths {
            let backup_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&backup_url).await {
                if response.status_code == 200
                    && response.body.contains("DB_PASSWORD")
                    && response.body.contains("DB_NAME")
                    && response.body.contains("define(")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "WordPress wp-config Backup Exposed",
                        &backup_url,
                        &format!(
                            "Backup copy of wp-config.php at {} is publicly readable — exposes database credentials and authentication salts/keys",
                            path
                        ),
                        Severity::Critical,
                        "CWE-538",
                    ));
                    break;
                }
            }
        }

        // Test: readme.html version disclosure (precise — only flag if WordPress version regex matches)
        let readme_url = format!("{}/readme.html", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&readme_url).await {
            if response.status_code == 200 {
                if let Ok(re) =
                    regex::Regex::new(r"(?i)Version\s+(\d+\.\d+(?:\.\d+)?)")
                {
                    if response.body.contains("WordPress") {
                        if let Some(caps) = re.captures(&response.body) {
                            if let Some(version) = caps.get(1) {
                                vulnerabilities.push(self.create_vulnerability(
                                    "WordPress readme.html Exposed",
                                    &readme_url,
                                    &format!(
                                        "Default readme.html is accessible and discloses WordPress version {}",
                                        version.as_str()
                                    ),
                                    Severity::Low,
                                    "CWE-200",
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan Spring Boot Actuator endpoints.
    ///
    /// Actuator endpoints (especially /actuator/env, /heapdump, /configprops, /beans)
    /// are one of the most consistently impactful sensitive-data findings on Java apps:
    /// they leak full environment, datasource URLs, secret keys, and even allow
    /// memory dump downloads. We only flag if the response body contains the
    /// structural marker for that specific endpoint, never on status code alone.
    async fn scan_spring_boot_actuator(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let base = url.trim_end_matches('/');

        // First fetch /actuator (or /manage, /admin/actuator) — the discovery endpoint.
        // We only continue if it returns the Spring HAL _links structure, avoiding
        // false positives on generic 200 OK pages.
        let discovery_prefixes = ["/actuator", "/manage", "/admin/actuator", "/management"];
        let mut active_prefix: Option<&str> = None;

        for prefix in &discovery_prefixes {
            tests_run += 1;
            let disco_url = format!("{}{}", base, prefix);
            if let Ok(response) = self.http_client.get(&disco_url).await {
                if response.status_code == 200
                    && response.body.contains("\"_links\"")
                    && (response.body.contains("\"self\"")
                        || response.body.contains("\"href\""))
                    && response.body.contains("\"href\":\"")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "Spring Boot Actuator Discovery Exposed",
                        &disco_url,
                        "Spring Boot Actuator discovery endpoint is publicly accessible. The HAL _links response enumerates all enabled management endpoints, which is the entry point for env/heapdump/configprops disclosure.",
                        Severity::Medium,
                        "CWE-200",
                    ));
                    active_prefix = Some(prefix);
                    break;
                }
            }
        }

        let prefix = match active_prefix {
            Some(p) => p,
            None => return Ok((vulnerabilities, tests_run)),
        };

        // Per-endpoint targeted checks. (path, body marker(s) — ALL must match,
        // human label, severity, cwe).
        let actuator_endpoints: &[(&str, &[&str], &str, Severity, &str)] = &[
            // /env leaks the full environment, including JDBC URLs, passwords (often masked
            // but the keys reveal where secrets live), and active profiles.
            (
                "/env",
                &["\"activeProfiles\"", "\"propertySources\""],
                "Spring Boot /env Exposed",
                Severity::Critical,
                "CWE-200",
            ),
            // /heapdump is a downloadable JVM heap (HPROF) — strings/passwords harvestable.
            // The HTTP response starts with the HPROF magic "JAVA PROFILE".
            (
                "/heapdump",
                &["JAVA PROFILE"],
                "Spring Boot /heapdump Exposed (JVM Memory Dump)",
                Severity::Critical,
                "CWE-200",
            ),
            // /configprops gives all @ConfigurationProperties beans with their resolved values.
            (
                "/configprops",
                &["\"contexts\"", "\"beans\""],
                "Spring Boot /configprops Exposed",
                Severity::High,
                "CWE-200",
            ),
            // /beans — leaks application architecture, every Spring bean, package paths.
            (
                "/beans",
                &["\"contexts\"", "\"beans\"", "\"scope\""],
                "Spring Boot /beans Exposed",
                Severity::Medium,
                "CWE-200",
            ),
            // /mappings — full route table, including hidden admin endpoints.
            (
                "/mappings",
                &["\"contexts\"", "\"dispatcherServlets\""],
                "Spring Boot /mappings Exposed (Route Enumeration)",
                Severity::Medium,
                "CWE-200",
            ),
            // /trace and /httptrace — recent HTTP requests including Authorization headers
            // and session cookies on misconfigured apps.
            (
                "/trace",
                &["\"timestamp\"", "\"method\"", "\"path\""],
                "Spring Boot /trace Exposed (Request History)",
                Severity::High,
                "CWE-532",
            ),
            (
                "/httptrace",
                &["\"traces\"", "\"timestamp\""],
                "Spring Boot /httptrace Exposed (Request History)",
                Severity::High,
                "CWE-532",
            ),
            // /loggers — listing levels is informational, but POST allows enabling
            // DEBUG/TRACE which leads to sensitive log content downstream.
            (
                "/loggers",
                &["\"loggers\"", "\"configuredLevel\""],
                "Spring Boot /loggers Exposed",
                Severity::Medium,
                "CWE-200",
            ),
            // /threaddump — full thread stacks, sometimes containing query params/state.
            (
                "/threaddump",
                &["\"threads\"", "\"threadName\""],
                "Spring Boot /threaddump Exposed",
                Severity::Medium,
                "CWE-200",
            ),
            // /metrics — alone is informational but useful in chained exploits.
            (
                "/metrics",
                &["\"names\""],
                "Spring Boot /metrics Exposed",
                Severity::Low,
                "CWE-200",
            ),
            // /info — reveals git commit, build version, sometimes maven repo data.
            (
                "/info",
                &["\"build\"", "\"version\""],
                "Spring Boot /info Exposed",
                Severity::Low,
                "CWE-200",
            ),
            // /gateway/routes — Spring Cloud Gateway: full upstream service list (SSRF surface).
            (
                "/gateway/routes",
                &["\"route_id\"", "\"predicate\""],
                "Spring Cloud Gateway /gateway/routes Exposed",
                Severity::High,
                "CWE-918",
            ),
        ];

        for (endpoint, markers, label, severity, cwe) in actuator_endpoints {
            tests_run += 1;
            let test_url = format!("{}{}{}", base, prefix, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code != 200 {
                    continue;
                }
                let all_match = markers.iter().all(|m| response.body.contains(m));
                if all_match {
                    info!("Actuator endpoint exposed: {}", test_url);
                    vulnerabilities.push(self.create_vulnerability(
                        label,
                        &test_url,
                        &format!(
                            "Spring Boot Actuator endpoint {}{} responds with the expected payload structure, confirming it is publicly accessible without auth.",
                            prefix, endpoint
                        ),
                        severity.clone(),
                        cwe,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Extract __NEXT_DATA__ from HTML
    fn extract_next_data(&self, html: &str) -> Option<String> {
        if let Some(start) = html.find("__NEXT_DATA__") {
            if let Some(data_start) = html[start..].find('{') {
                let json_start = start + data_start;
                let mut depth = 0;
                let mut in_string = false;
                let mut escape = false;

                for (i, ch) in html[json_start..].chars().enumerate() {
                    if escape {
                        escape = false;
                        continue;
                    }
                    if ch == '\\' {
                        escape = true;
                        continue;
                    }
                    if ch == '"' {
                        in_string = !in_string;
                    }
                    if !in_string {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                            if depth == 0 {
                                return Some(html[json_start..json_start + i + 1].to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract WordPress version
    fn extract_wordpress_version(&self, html: &str) -> Option<String> {
        if let Some(start) = html.find("wp-content") {
            let search_area =
                &html[floor_char_boundary(html, start.saturating_sub(200))..ceil_char_boundary(html, start.saturating_add(200).min(html.len()))];
            if let Some(version_match) = regex::Regex::new(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)")
                .ok()
                .and_then(|re| re.captures(search_area))
            {
                return Some(version_match[1].to_string());
            }
        }
        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("framework_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::Medium,
            category: "Framework Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Next.js Sensitive Data Exposure" => {
                "Remove sensitive data from getServerSideProps and getStaticProps. Use environment variables for secrets. Implement proper API routes for sensitive operations.".to_string()
            }
            "Next.js API Route Exposed" => {
                "Implement authentication middleware for API routes. Use NextAuth.js or custom auth. Validate requests and implement rate limiting.".to_string()
            }
            "React dangerouslySetInnerHTML Usage" | "Vue v-html Usage Detected" | "Angular bypassSecurityTrust Usage" => {
                "Avoid using HTML injection methods. Sanitize user input with DOMPurify. Use framework's built-in escaping. Implement Content Security Policy.".to_string()
            }
            "Django Debug Mode Enabled" | "Laravel Debug Mode Enabled" => {
                "Disable debug mode in production. Set DEBUG=False in settings. Configure proper error logging. Remove debug toolbar.".to_string()
            }
            "Django Admin Panel Exposed" | "Laravel Telescope Exposed" => {
                "Restrict admin panel access by IP. Use VPN for admin access. Implement strong authentication. Change default admin URL.".to_string()
            }
            "Laravel Horizon Exposed" => {
                "Add Horizon::auth() in app/Providers/HorizonServiceProvider.php to gate access by user role/IP. Never deploy Horizon to production behind only middleware('web') alone.".to_string()
            }
            "Laravel Debugbar Enabled" => {
                "Set APP_DEBUG=false and DEBUGBAR_ENABLED=false in your .env for production. Add `barryvdh/laravel-debugbar` to `dont-discover` or require-dev only.".to_string()
            }
            "Laravel Ignition Endpoint Exposed" => {
                "Set APP_DEBUG=false in production. Update facade/ignition to the latest patched version (CVE-2021-3129 affects <2.5.2). Restrict /_ignition/* at the reverse proxy.".to_string()
            }
            "Laravel storage/logs/laravel.log Exposed" => {
                "storage/ should never be web-accessible. Verify your web server document root is set to /public, not the project root. Add an explicit deny rule for storage/ in nginx/Apache config.".to_string()
            }
            "Django Silk Profiler Exposed" | "Django Debug Toolbar Enabled" => {
                "These tools must only run when DEBUG=True in development. Verify INSTALLED_APPS in production doesn't include `silk` / `debug_toolbar`, and gate the URL include with `if settings.DEBUG`.".to_string()
            }
            t if t.starts_with("Spring Boot ") || t.starts_with("Spring Cloud Gateway ") => {
                "Set management.endpoints.web.exposure.include=health,info (or just `health`). Place actuator under a separate management.server.port bound to a non-public interface. Add Spring Security to require auth for /actuator/**.".to_string()
            }
            "WordPress wp-content/debug.log Exposed" => {
                "Set WP_DEBUG_LOG to a path outside the web root, or add an Apache/nginx deny rule for *.log under wp-content/. Disable WP_DEBUG in production.".to_string()
            }
            "WordPress wp-config Backup Exposed" => {
                "Immediately rotate DB password and authentication keys/salts. Remove the backup file. Configure the web server to block hidden/backup file extensions (.bak, .swp, ~, .old, .save).".to_string()
            }
            "WordPress readme.html Exposed" => {
                "Delete readme.html from the WordPress install (it is regenerated on update — automate its removal in deployment).".to_string()
            }
            "WordPress xmlrpc.php Enabled" => {
                "Disable xmlrpc.php if not needed. Use security plugins to block xmlrpc. Implement rate limiting. Monitor xmlrpc access logs.".to_string()
            }
            "WordPress User Enumeration" => {
                "Disable author archives. Use security plugins to prevent enumeration. Implement random user IDs. Configure proper permalinks.".to_string()
            }
            _ => {
                "Follow framework security best practices. Keep framework updated. Disable debug mode in production. Implement proper authentication and authorization.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> FrameworkVulnerabilitiesScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        FrameworkVulnerabilitiesScanner::new(client)
    }

    #[test]
    fn test_extract_next_data() {
        let scanner = create_test_scanner();

        let html =
            r#"<script>__NEXT_DATA__ = {"props":{"pageProps":{"secret":"test123"}}};</script>"#;
        let result = scanner.extract_next_data(html);

        assert!(result.is_some());
        let data = result.unwrap();
        assert!(data.contains("props"));
        assert!(data.contains("secret"));
    }

    #[test]
    fn test_extract_wordpress_version() {
        let scanner = create_test_scanner();

        let html = r#"<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/test""#;
        let version = scanner.extract_wordpress_version(html);

        assert_eq!(version, Some("6.4.2".to_string()));
    }

    #[test]
    fn test_framework_detection() {
        let scanner = create_test_scanner();

        assert!(scanner.extract_next_data("__NEXT_DATA__ = {}").is_some());
        assert!(scanner.extract_next_data("no framework here").is_none());
    }
}
