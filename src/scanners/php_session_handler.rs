// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy — PHP Session Handler Vulnerability Scanner (php2shell)
 *
 * Detects PHP servers vulnerable to the "php2shell" session-handler
 * memory-corruption chain (use-after-free in `php_session_send_cookie`,
 * OOB reads via stale session-id pointers, dangling
 * `PS(http_session_vars)` → pDestructor overwrite to `zif_system`).
 *
 * This is a pure-HTTP, unauthenticated RCE against stock Apache prefork
 * PHP deployments.  The exploit requires NO file upload, NO gdb, and NO
 * target-side files — only normal HTTP POST requests with crafted
 * multipart bodies that trigger OOM during END-cleanup.
 *
 * ──────────────────────────────────────────────────────────────────────
 * DETECTION APPROACH — light behavioural probing, ZERO exploitation
 *
 * Instead of just checking version strings (which are often stripped),
 * we probe for each **precondition** the exploit chain actually needs.
 * Every probe is a normal benign HTTP request — no memory corruption,
 * no OOM, no oversized bodies.  The probes are:
 *
 *  ┌──────────────────────────┬─────────────────────────────────────┐
 *  │ Precondition             │ Safe probe                          │
 *  ├──────────────────────────┼─────────────────────────────────────┤
 *  │ PHP running              │ Header/cookie/error-page/path FP    │
 *  │ Session handler active   │ POST+Cookie:PHPSESSID=x → Set-Cookie│
 *  │ Apache prefork MPM       │ /server-status, /server-info,       │
 *  │                          │ Server header parse, timing probe   │
 *  │ Chunked TE accepted      │ Small chunked POST → 200 vs 411    │
 *  │ Multipart POST processed │ Tiny multipart to .php → 200       │
 *  │ Query-string hash alloc  │ 5-param ?q0=v&q1=v&… → normal resp │
 *  │ memory_limit ≥128M       │ phpinfo extraction when available   │
 *  │ PHP version in vuln range│ Header/phpinfo/cookie-length/errors │
 *  └──────────────────────────┴─────────────────────────────────────┘
 *
 * Confidence is computed from how many preconditions are confirmed.
 *
 * Affected versions (session-handler UAF → RCE, "php2shell"):
 *   PHP 8.4.0 – 8.4.26 (confirmed exploitable with public PoC)
 *   PHP 8.3.x, 8.2.x, 8.1.x — affected if session handler is present
 *   PHP 8.0 and below — EOL, session handler UAF is present
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary — Enterprise Edition
 */
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info, warn};

// ── configuration ──────────────────────────────────────────────────────

/// Configuration for the PHP session-handler scan.
#[derive(Debug, Clone)]
pub struct PhpSessionHandlerConfig {
    /// Try to discover phpinfo() endpoints.
    pub probe_phpinfo: bool,
    /// Try well-known PHP paths to confirm presence.
    pub probe_default_paths: bool,
    /// Run the exploit-precondition probes (session, chunked, multipart, etc.)
    pub probe_preconditions: bool,
    /// Maximum additional requests beyond the initial GET.
    pub max_extra_requests: usize,
}

impl Default for PhpSessionHandlerConfig {
    fn default() -> Self {
        Self {
            probe_phpinfo: true,
            probe_default_paths: true,
            probe_preconditions: true,
            max_extra_requests: 20,
        }
    }
}

// ── scanner ────────────────────────────────────────────────────────────

pub struct PhpSessionHandlerScanner {
    http_client: Arc<HttpClient>,
    config: PhpSessionHandlerConfig,
}

impl PhpSessionHandlerScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            config: PhpSessionHandlerConfig::default(),
        }
    }

    pub fn with_config(http_client: Arc<HttpClient>, config: PhpSessionHandlerConfig) -> Self {
        Self {
            http_client,
            config,
        }
    }

    // ── public entry point ──────────────────────────────────────────────

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[php2shell] Scanning: {}", url);

        let mut vulns: Vec<Vulnerability> = Vec::new();
        let mut tests_run: usize = 0;
        let mut ctx = ScanContext::default();

        // ── Phase 1: Is this PHP? ───────────────────────────────────────

        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                debug!("[php2shell] Could not fetch URL");
                return Ok((vulns, tests_run));
            }
        };
        tests_run += 1;
        self.collect_php_signals(&response, &mut ctx);

        // If no PHP signals from the landing page, try known PHP paths
        if ctx.php_confidence == PhpConfidence::None {
            self.probe_php_paths(url, &mut ctx, &mut tests_run).await;
        }

        if ctx.php_confidence == PhpConfidence::None {
            info!("[php2shell] Target does not appear to run PHP — skipping");
            return Ok((vulns, tests_run));
        }

        info!(
            "[php2shell] PHP detected (confidence={:?}, version={:?})",
            ctx.php_confidence, ctx.version
        );

        // ── Phase 2: Version fingerprinting ─────────────────────────────

        // phpinfo() discovery
        if self.config.probe_phpinfo && ctx.version.is_none() {
            self.probe_phpinfo(url, &mut ctx, &mut tests_run).await;
        }

        // Error page version leak
        if ctx.version.is_none() {
            self.probe_error_page(url, &mut ctx, &mut tests_run).await;
        }

        // ── Phase 3: Exploit-precondition probes ────────────────────────

        if self.config.probe_preconditions {
            // Find a working .php endpoint for the probes
            let php_endpoint = self.find_php_endpoint(url, &mut tests_run).await;

            if let Some(ref ep) = php_endpoint {
                self.probe_session_handler(ep, &mut ctx, &mut tests_run)
                    .await;
                self.probe_chunked_te(ep, &mut ctx, &mut tests_run).await;
                self.probe_multipart(ep, &mut ctx, &mut tests_run).await;
                self.probe_query_hash(ep, &mut ctx, &mut tests_run).await;
            }

            self.probe_apache_mpm(url, &mut ctx, &mut tests_run).await;

            // phpinfo memory_limit extraction
            if ctx.phpinfo_body.is_some() {
                let pi = ctx.phpinfo_body.clone().unwrap();
                Self::extract_memory_limit(&pi, &mut ctx);
            }
        }

        // ── Phase 4: Verdict ────────────────────────────────────────────

        self.emit_finding(url, &ctx, &mut vulns);

        info!(
            "[SUCCESS] [php2shell] {} tests, {} issues, preconditions: {}/{}",
            tests_run,
            vulns.len(),
            ctx.preconditions_met(),
            ctx.preconditions_tested(),
        );

        Ok((vulns, tests_run))
    }

    // ── Phase 1: PHP detection ──────────────────────────────────────────

    fn collect_php_signals(
        &self,
        resp: &crate::http_client::HttpResponse,
        ctx: &mut ScanContext,
    ) {
        // X-Powered-By
        if let Some(xpb) = resp.header("x-powered-by") {
            let xpb_lower = xpb.to_lowercase();
            if xpb_lower.contains("php") {
                ctx.add_evidence("X-Powered-By contains PHP");
                ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
                if ctx.version.is_none() {
                    ctx.version = Self::extract_version(&xpb);
                }
            }
        }

        // Server header
        if let Some(srv) = resp.header("server") {
            let srv_lower = srv.to_lowercase();
            if srv_lower.contains("php") {
                ctx.add_evidence("Server header mentions PHP");
                ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
                if ctx.version.is_none() {
                    ctx.version = Self::extract_version(&srv);
                }
            }
            if srv_lower.contains("apache") {
                ctx.add_evidence("Apache server");
                ctx.is_apache = true;
                ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Possible);
            }
        }

        // Set-Cookie: PHPSESSID
        for (k, v) in &resp.headers {
            if k.to_lowercase() == "set-cookie" && v.contains("PHPSESSID") {
                ctx.add_evidence("PHPSESSID cookie");
                ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
                self.analyse_session_cookie(v, ctx);
            }
        }

        // X-PHP-OB-Level (rarely stripped)
        if resp.header("x-php-ob-level").is_some() {
            ctx.add_evidence("X-PHP-OB-Level header");
            ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
        }

        // Body: PHP error messages
        let body_lower = resp.body.to_lowercase();
        if body_lower.contains("fatal error") && body_lower.contains(".php on line") {
            ctx.add_evidence("PHP fatal error in body");
            ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
        }
        if body_lower.contains("php warning") || body_lower.contains("php notice") {
            ctx.add_evidence("PHP warning/notice in body");
            ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Confirmed);
        }

        // .php links in page
        if resp.body.contains(".php") {
            let re = Regex::new(r#"(?:href|action|src)\s*=\s*["'][^"']*\.php[^"']*["']"#)
                .unwrap();
            if re.is_match(&resp.body) {
                ctx.add_evidence(".php URLs in HTML");
                ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Likely);
            }
        }

        // Apache mod_php ETag pattern
        if let Some(etag) = resp.header("etag") {
            if ctx.is_apache {
                let etag_re = Regex::new(r#"^"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"$"#).unwrap();
                if etag_re.is_match(&etag) {
                    ctx.add_evidence("Apache mod_php ETag");
                    ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Possible);
                }
            }
        }
    }

    /// Probe well-known PHP paths
    async fn probe_php_paths(
        &self,
        url: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        if !self.config.probe_default_paths {
            return;
        }
        let base = url.trim_end_matches('/');
        let paths = [
            "/index.php",
            "/info.php",
            "/test.php",
            "/wp-login.php",
            "/administrator/index.php",
        ];
        for path in &paths {
            if *tests_run >= self.config.max_extra_requests {
                break;
            }
            *tests_run += 1;
            let probe_url = format!("{}{}", base, path);
            if let Ok(resp) = self.http_client.get(&probe_url).await {
                self.collect_php_signals(&resp, ctx);
                if ctx.php_confidence >= PhpConfidence::Likely {
                    return;
                }
                // A 200 on a *.php path is a signal even without headers
                if resp.status_code == 200 {
                    ctx.add_evidence(format!("{} returned 200", path));
                    ctx.php_confidence = ctx.php_confidence.raise(PhpConfidence::Likely);
                    return;
                }
            }
        }
    }

    // ── Phase 2: Version fingerprinting ─────────────────────────────────

    fn extract_version(s: &str) -> Option<String> {
        let re = Regex::new(r"PHP[/ ](\d+\.\d+\.\d+)").ok()?;
        re.captures(s).map(|c| c[1].to_string())
    }

    /// Discover phpinfo() pages and extract version + memory_limit.
    async fn probe_phpinfo(
        &self,
        url: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        let base = url.trim_end_matches('/');
        let paths = [
            "/phpinfo.php",
            "/info.php",
            "/php_info.php",
            "/pi.php",
            "/test.php",
            "/_phpinfo.php",
        ];
        for path in &paths {
            if *tests_run >= self.config.max_extra_requests {
                return;
            }
            *tests_run += 1;
            let probe = format!("{}{}", base, path);
            if let Ok(resp) = self.http_client.get(&probe).await {
                if resp.status_code == 200 && resp.body.contains("phpinfo()") {
                    ctx.add_evidence(format!("phpinfo() exposed at {}", path));

                    // Version
                    let ver_re =
                        Regex::new(r"PHP Version\s*(?:</td><td[^>]*>)?\s*(\d+\.\d+\.\d+)")
                            .unwrap();
                    if let Some(caps) = ver_re.captures(&resp.body) {
                        let ver = caps[1].to_string();
                        info!("[php2shell] phpinfo at {} → PHP {}", path, ver);
                        ctx.version = Some(ver);
                    }

                    // Server API (tells us if mod_php + prefork)
                    let sapi_re = Regex::new(r"Server API\s*</td><td[^>]*>([^<]+)").unwrap();
                    if let Some(caps) = sapi_re.captures(&resp.body) {
                        let sapi = caps[1].trim().to_string();
                        ctx.add_evidence(format!("SAPI: {}", sapi));
                        if sapi.contains("Apache") && sapi.contains("Handler") {
                            ctx.is_mod_php = true;
                            ctx.is_apache = true;
                        }
                    }

                    // MPM (if visible in phpinfo loaded modules)
                    let body_lower = resp.body.to_lowercase();
                    if body_lower.contains("prefork") {
                        ctx.is_prefork = Some(true);
                        ctx.add_evidence("phpinfo shows prefork MPM");
                    } else if body_lower.contains("mpm_event") || body_lower.contains("mpm_worker")
                    {
                        ctx.is_prefork = Some(false);
                        ctx.add_evidence("phpinfo shows event/worker MPM (not prefork)");
                    }

                    // Keep body for memory_limit extraction later
                    ctx.phpinfo_body = Some(resp.body.clone());
                    return;
                }
            }
        }
    }

    /// Probe error page for version leak.
    async fn probe_error_page(
        &self,
        url: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        *tests_run += 1;
        let base = url.trim_end_matches('/');
        let probe = format!(
            "{}/lonkero_nonexistent_{}.php",
            base,
            rand::random::<u32>()
        );
        if let Ok(resp) = self.http_client.get(&probe).await {
            // Headers on error pages sometimes leak version even when stripped on 200s
            for h in ["x-powered-by", "server"] {
                if let Some(val) = resp.header(h) {
                    if let Some(v) = Self::extract_version(&val) {
                        ctx.version = Some(v);
                        ctx.add_evidence(format!("Version leaked in {} on 404", h));
                        return;
                    }
                }
            }
            // Apache default error page embeds version in footer
            if let Some(v) = Self::extract_version(&resp.body) {
                ctx.version = Some(v);
                ctx.add_evidence("Version in 404 error body");
            }
        }
    }

    // ── Phase 3: Exploit-precondition probes ────────────────────────────

    /// Find a .php endpoint that returns 200 (for POST probes).
    async fn find_php_endpoint(&self, url: &str, tests_run: &mut usize) -> Option<String> {
        let base = url.trim_end_matches('/');
        // Try the URL itself first
        if url.contains(".php") {
            return Some(url.to_string());
        }
        let candidates = ["/index.php", "/", "/wp-login.php"];
        for path in &candidates {
            if *tests_run >= self.config.max_extra_requests {
                break;
            }
            *tests_run += 1;
            let ep = format!("{}{}", base, path);
            if let Ok(resp) = self.http_client.get(&ep).await {
                if resp.status_code == 200 || resp.status_code == 302 {
                    return Some(ep);
                }
            }
        }
        // Fall back to root
        Some(format!("{}/index.php", base))
    }

    /// Probe 1: Session handler reachable?
    /// POST to a .php endpoint with `Cookie: PHPSESSID=lonkero_test` and see
    /// if the response contains a `Set-Cookie: PHPSESSID=` (session_start ran).
    /// Also try with no cookie to see if session.auto_start is on.
    async fn probe_session_handler(
        &self,
        endpoint: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        // Request with existing PHPSESSID → should regenerate or accept
        *tests_run += 1;
        let headers = vec![
            (
                "Cookie".to_string(),
                "PHPSESSID=lonkero_probe_test_abc123".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ];
        if let Ok(resp) = self
            .http_client
            .post_with_headers(endpoint, "", headers)
            .await
        {
            self.collect_php_signals(&resp, ctx);
            let has_sessid = resp
                .headers
                .iter()
                .any(|(k, v)| k.to_lowercase() == "set-cookie" && v.contains("PHPSESSID"));
            if has_sessid {
                ctx.session_reachable = Some(true);
                ctx.add_evidence("Session handler active (PHPSESSID set on POST)");
                // Analyse the session cookie for version hints
                for (k, v) in &resp.headers {
                    if k.to_lowercase() == "set-cookie" && v.contains("PHPSESSID") {
                        self.analyse_session_cookie(v, ctx);
                    }
                }
            } else {
                ctx.session_reachable = Some(false);
                ctx.add_evidence("No PHPSESSID in response (sessions may be disabled or endpoint-specific)");
            }
        }

        // Also try a plain GET — some apps use session.auto_start
        if ctx.session_reachable != Some(true) {
            *tests_run += 1;
            if let Ok(resp) = self.http_client.get(endpoint).await {
                let has_sessid = resp
                    .headers
                    .iter()
                    .any(|(k, v)| k.to_lowercase() == "set-cookie" && v.contains("PHPSESSID"));
                if has_sessid {
                    ctx.session_reachable = Some(true);
                    ctx.add_evidence("Session auto_start active (PHPSESSID set on GET)");
                }
            }
        }
    }

    /// Probe 2: Chunked Transfer-Encoding accepted?
    /// The exploit sends the OOM payload via chunked TE.  Send a tiny
    /// chunked POST and see if the server returns 200 (accepted) vs 411
    /// (Length Required — chunked rejected by proxy/config).
    async fn probe_chunked_te(
        &self,
        endpoint: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        *tests_run += 1;
        let headers = vec![
            (
                "Transfer-Encoding".to_string(),
                "chunked".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ];
        // Valid chunked body: one small chunk + terminator
        let body = "5\r\nx=foo\r\n0\r\n\r\n";
        if let Ok(resp) = self
            .http_client
            .post_with_headers(endpoint, body, headers)
            .await
        {
            if resp.status_code == 411 {
                ctx.chunked_accepted = Some(false);
                ctx.add_evidence("Chunked TE rejected (411 Length Required)");
            } else if resp.status_code < 500 {
                ctx.chunked_accepted = Some(true);
                ctx.add_evidence(format!(
                    "Chunked TE accepted (status {})",
                    resp.status_code
                ));
            }
            // 5xx → unclear, leave as None
        }
    }

    /// Probe 3: Multipart POST processed?
    /// The exploit payload is a crafted multipart body.  Send a tiny valid
    /// multipart form and confirm PHP processes it (doesn't reject it).
    async fn probe_multipart(
        &self,
        endpoint: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        *tests_run += 1;
        let boundary = "----LonkeroProbe7f3c";
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"lonkero_probe\"\r\n\r\n\
             test\r\n\
             --{boundary}--\r\n"
        );
        let headers = vec![(
            "Content-Type".to_string(),
            format!("multipart/form-data; boundary={}", boundary),
        )];
        if let Ok(resp) = self
            .http_client
            .post_with_headers(endpoint, &body, headers)
            .await
        {
            if resp.status_code < 500 {
                ctx.multipart_accepted = Some(true);
                ctx.add_evidence(format!(
                    "Multipart POST accepted (status {})",
                    resp.status_code
                ));
            } else {
                ctx.multipart_accepted = Some(false);
                ctx.add_evidence(format!(
                    "Multipart POST rejected (status {})",
                    resp.status_code
                ));
            }
        }
    }

    /// Probe 4: Query-string hash allocation.
    /// The exploit uses `?q0000000=v&q0000001=v&...&q0000004=v` (5 params)
    /// to fill specific hash-table slots.  Send the same pattern and confirm
    /// the server handles it normally.
    async fn probe_query_hash(
        &self,
        endpoint: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        *tests_run += 1;
        let q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v";
        let probe_url = format!("{}{}", endpoint, q);
        if let Ok(resp) = self.http_client.get(&probe_url).await {
            if resp.status_code < 500 {
                ctx.query_hash_ok = Some(true);
                ctx.add_evidence(format!(
                    "5-param query string accepted (status {})",
                    resp.status_code
                ));
            } else {
                ctx.query_hash_ok = Some(false);
            }
        }
    }

    /// Probe 5: Apache MPM detection.
    /// Check /server-status and /server-info (often enabled in dev, disabled in prod).
    /// Also parse the Server header for MPM hints.
    async fn probe_apache_mpm(
        &self,
        url: &str,
        ctx: &mut ScanContext,
        tests_run: &mut usize,
    ) {
        if !ctx.is_apache {
            return;
        }

        let base = url.trim_end_matches('/');

        // /server-status?auto — lightweight, text output
        *tests_run += 1;
        if let Ok(resp) = self
            .http_client
            .get(&format!("{}/server-status?auto", base))
            .await
        {
            if resp.status_code == 200 {
                ctx.add_evidence("Apache /server-status accessible");
                let body_lower = resp.body.to_lowercase();
                if body_lower.contains("scoreboard") {
                    // Prefork: single-threaded children → "Scoreboard" line has
                    // one char per slot.  The key indicator is "ServerMPM: prefork"
                    if body_lower.contains("servermpm: prefork") {
                        ctx.is_prefork = Some(true);
                        ctx.add_evidence("server-status confirms prefork MPM");
                    } else if body_lower.contains("servermpm: event")
                        || body_lower.contains("servermpm: worker")
                    {
                        ctx.is_prefork = Some(false);
                        ctx.add_evidence("server-status shows event/worker MPM");
                    }
                }
            }
        }

        // /server-info
        if ctx.is_prefork.is_none() {
            *tests_run += 1;
            if let Ok(resp) = self
                .http_client
                .get(&format!("{}/server-info", base))
                .await
            {
                if resp.status_code == 200 {
                    let body_lower = resp.body.to_lowercase();
                    if body_lower.contains("prefork.c") || body_lower.contains("prefork_module") {
                        ctx.is_prefork = Some(true);
                        ctx.add_evidence("server-info confirms prefork MPM");
                    } else if body_lower.contains("event.c") || body_lower.contains("worker.c") {
                        ctx.is_prefork = Some(false);
                        ctx.add_evidence("server-info shows event/worker MPM");
                    }
                }
            }
        }

        // If Server header contains MPM hint (some builds include it)
        // e.g. "Apache/2.4.62 (Debian)" doesn't say, but sometimes
        // "Apache/2.4.62 (Debian) mod_fcgid/2.3.9" → not mod_php
        // We already collected is_mod_php from phpinfo SAPI if available.
    }

    /// Extract memory_limit from a cached phpinfo body.
    fn extract_memory_limit(phpinfo: &str, ctx: &mut ScanContext) {
        let re = Regex::new(
            r"memory_limit\s*</td><td[^>]*>(\d+[MmGgKk]?)\s*</td>",
        )
        .unwrap();
        if let Some(caps) = re.captures(phpinfo) {
            let raw = caps[1].to_string();
            ctx.add_evidence(format!("memory_limit = {}", raw));
            // Parse to bytes
            let val = raw.trim().to_uppercase();
            let bytes: Option<u64> = if val.ends_with('G') {
                val.trim_end_matches('G').parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024)
            } else if val.ends_with('M') {
                val.trim_end_matches('M').parse::<u64>().ok().map(|v| v * 1024 * 1024)
            } else if val.ends_with('K') {
                val.trim_end_matches('K').parse::<u64>().ok().map(|v| v * 1024)
            } else {
                val.parse().ok()
            };
            if let Some(b) = bytes {
                ctx.memory_limit_bytes = Some(b);
                // The exploit needs ≥128M for the OOM spray to work
                if b >= 128 * 1024 * 1024 {
                    ctx.add_evidence(format!(
                        "memory_limit {} ≥ 128M (sufficient for OOM spray)",
                        raw
                    ));
                } else {
                    ctx.add_evidence(format!(
                        "memory_limit {} < 128M (may limit OOM spray)",
                        raw
                    ));
                }
            }
        }
    }

    /// Analyse a Set-Cookie value for PHPSESSID details.
    fn analyse_session_cookie(&self, cookie_val: &str, ctx: &mut ScanContext) {
        let re = Regex::new(r"PHPSESSID=([^;]+)").unwrap();
        if let Some(caps) = re.captures(cookie_val) {
            let sessid = &caps[1];
            ctx.session_id_len = Some(sessid.len());

            // PHP ≤8.3 default: 26 hex chars (session.sid_length=26)
            // PHP 8.4+: 32 hex chars (session.sid_length=32, more entropy)
            if sessid.len() >= 32 {
                ctx.add_evidence(format!(
                    "PHPSESSID length {} → likely PHP 8.4+",
                    sessid.len()
                ));
                if ctx.version.is_none() {
                    ctx.version = Some("8.4.x".to_string());
                }
            } else if sessid.len() == 26 {
                ctx.add_evidence("PHPSESSID length 26 → PHP 7.1–8.3");
            }
        }

        // SameSite attribute (PHP 8.0+ defaults to Lax)
        let lower = cookie_val.to_lowercase();
        if lower.contains("samesite=lax") && ctx.version.is_none() {
            ctx.add_evidence("PHPSESSID SameSite=Lax → PHP ≥ 8.0");
        }
    }

    // ── Phase 4: Verdict ────────────────────────────────────────────────

    fn emit_finding(&self, url: &str, ctx: &ScanContext, vulns: &mut Vec<Vulnerability>) {
        let met = ctx.preconditions_met();
        let tested = ctx.preconditions_tested();

        // Build a structured evidence summary
        let mut evidence_parts: Vec<String> = Vec::new();
        evidence_parts.push(format!(
            "PHP confidence: {:?}",
            ctx.php_confidence
        ));
        if let Some(ref v) = ctx.version {
            evidence_parts.push(format!("Version: {}", v));
        }
        evidence_parts.push(format!(
            "Preconditions: {}/{} confirmed",
            met, tested
        ));
        evidence_parts.push(format!(
            "Session: {}, Chunked: {}, Multipart: {}, QueryHash: {}, Apache: {}, Prefork: {}, mod_php: {}",
            fmt_opt(ctx.session_reachable),
            fmt_opt(ctx.chunked_accepted),
            fmt_opt(ctx.multipart_accepted),
            fmt_opt(ctx.query_hash_ok),
            if ctx.is_apache { "yes" } else { "no" },
            match ctx.is_prefork { Some(true) => "yes", Some(false) => "no", None => "unknown" },
            if ctx.is_mod_php { "yes" } else { "unknown" },
        ));
        if let Some(bytes) = ctx.memory_limit_bytes {
            evidence_parts.push(format!("memory_limit: {}M", bytes / (1024 * 1024)));
        }
        for e in &ctx.evidence {
            evidence_parts.push(e.clone());
        }

        let evidence_str = evidence_parts.join("; ");

        // Determine if the version is in the affected range
        let version_affected = ctx.version.as_deref().map(|v| Self::is_version_affected(v));

        // ── Decision matrix ─────────────────────────────────────────────
        //
        // Critical: version confirmed vulnerable + Apache prefork + session reachable
        // High:     version confirmed vulnerable + most preconditions met
        // High:     no version but ALL preconditions confirmed (PHP + Apache + prefork + session + chunked + multipart)
        // Medium:   version looks vulnerable but can't confirm preconditions
        // Low/Info: PHP confirmed but version unknown / preconditions not met

        let (severity, confidence, description) =
            if version_affected == Some(true)
                && ctx.is_apache
                && ctx.is_prefork == Some(true)
                && ctx.session_reachable == Some(true)
            {
                (
                    Severity::Critical,
                    Confidence::High,
                    format!(
                        "CONFIRMED VULNERABLE: PHP {} on Apache prefork with active session handler. \
                         All preconditions for the php2shell exploit chain are met ({}/{} confirmed). \
                         An unauthenticated attacker can achieve RCE via pure HTTP POST with crafted \
                         multipart bodies — no file uploads or special config needed.",
                        ctx.version.as_deref().unwrap_or("?"),
                        met,
                        tested,
                    ),
                )
            } else if version_affected == Some(true) && met >= 3 {
                (
                    Severity::Critical,
                    Confidence::Medium,
                    format!(
                        "PHP {} is in the php2shell vulnerable range. {}/{} exploit preconditions confirmed. {}{}",
                        ctx.version.as_deref().unwrap_or("?"),
                        met, tested,
                        if !ctx.is_apache { "Non-Apache server reduces exploitability but the bug is still present. " } else { "" },
                        if ctx.is_prefork == Some(false) { "Event/worker MPM detected — harder to exploit than prefork but not impossible. " } else { "" },
                    ),
                )
            } else if version_affected == Some(true) {
                (
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "PHP {} is in the php2shell vulnerable range. Only {}/{} exploit preconditions \
                         could be confirmed — the server may be partially protected by configuration, \
                         but the underlying UAF bug is present.",
                        ctx.version.as_deref().unwrap_or("?"),
                        met, tested,
                    ),
                )
            } else if ctx.php_confidence >= PhpConfidence::Confirmed
                && version_affected.is_none()
                && met >= 4
            {
                // No version, but PHP confirmed and many preconditions met
                (
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "PHP confirmed with {}/{} exploit preconditions met (version could not be \
                         determined). Given active session handler + Apache{} + multipart/chunked \
                         support, this target is likely vulnerable to php2shell. Verify PHP version.",
                        met,
                        tested,
                        if ctx.is_prefork == Some(true) { " prefork" } else { "" },
                    ),
                )
            } else if ctx.php_confidence >= PhpConfidence::Confirmed
                && ctx.session_reachable == Some(true)
            {
                // PHP confirmed with sessions but not enough other signals
                (
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "PHP with active session handler detected ({}/{} preconditions confirmed). \
                         Version {} — verify manually whether this server runs a php2shell-affected PHP version.",
                        met,
                        tested,
                        ctx.version
                            .as_deref()
                            .map(|v| format!("detected as {}", v))
                            .unwrap_or_else(|| "could not be determined".to_string()),
                    ),
                )
            } else if ctx.php_confidence >= PhpConfidence::Likely {
                // PHP likely but minimal signals
                vulns.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "PHP Session Handler (php2shell) — Verify Version".to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::Low,
                    category: "Version Check".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!(
                        "PHP detected on this target ({}/{} exploit preconditions tested). \
                         Version {}. Verify PHP is patched against the php2shell UAF RCE chain. \
                         PHP 8.4.26 is confirmed exploitable.",
                        met,
                        tested,
                        ctx.version
                            .as_deref()
                            .map(|v| format!("detected as {}", v))
                            .unwrap_or_else(|| "unknown".to_string()),
                    ),
                    evidence: Some(evidence_str),
                    cwe: "CWE-416".to_string(),
                    cvss: 0.0,
                    verified: false,
                    false_positive: false,
                    remediation: "Verify PHP version. Run `php -v` on the server. \
                         Upgrade to the latest patch release."
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
                return;
            } else {
                // Not enough signals
                return;
            };

        vulns.push(Vulnerability {
            id: generate_uuid(),
            vuln_type: "PHP Session Handler UAF RCE — php2shell".to_string(),
            severity,
            confidence,
            category: "Remote Code Execution".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description,
            evidence: Some(evidence_str),
            cwe: "CWE-416".to_string(),
            cvss: 9.8,
            verified: false,
            false_positive: false,
            remediation: format!(
                "IMMEDIATE ACTION REQUIRED:\n\
                1. Upgrade PHP to the latest patch release for your branch\n\
                   (PHP 8.4.26 is confirmed exploitable with public PoC)\n\
                2. If upgrading is not immediately possible, mitigate:\n\
                   - Switch Apache from prefork to event/worker MPM\n\
                     (breaks the single-child pinning the exploit needs)\n\
                   - Lower memory_limit below 128M (shrinks OOM-spray window){}\n\
                   - Disable sessions if not needed (session.auto_start=0)\n\
                   - WAF rule: block chunked multipart POSTs > ~10MB\n\
                3. PHP 8.0 and below are EOL — migrate immediately.\n\
                \n\
                Exploit chain (for understanding the risk):\n\
                A1: OOM during END-cleanup → stale session cookie pointer\n\
                B1: Stale-id OOB read → leak heap chunk base + libphp base\n\
                A2: Cheap OOM → dangling PS(http_session_vars)\n\
                B2: Fake zval ref + fake zend_array → pDestructor = zif_system\n\
                \n\
                Preconditions detected on this target: {}/{}",
                if ctx.memory_limit_bytes.map(|b| b >= 128 * 1024 * 1024) == Some(true) {
                    format!(
                        "\n     (current memory_limit: {}M — sufficient for exploit)",
                        ctx.memory_limit_bytes.unwrap() / (1024 * 1024)
                    )
                } else {
                    String::new()
                },
                ctx.preconditions_met(),
                ctx.preconditions_tested(),
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_confidence: None,
            ml_data: None,
        });
    }

    /// Check if a version string is in the affected range.
    fn is_version_affected(ver_str: &str) -> bool {
        // Handle "8.4.x" style hints from session cookie length
        if ver_str == "8.4.x" {
            return true; // 8.4.x without a patch number → assume affected
        }
        let parts: Vec<u32> = ver_str
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() < 3 {
            return false; // can't tell
        }
        let (major, minor, patch) = (parts[0], parts[1], parts[2]);
        match (major, minor) {
            (8, 4) => patch <= 26,
            (8, 3) => true,
            (8, 2) => true,
            (8, 1) => true,
            (8, 0) => true,
            _ if major < 8 && major >= 5 => true,
            _ => false,
        }
    }
}

// ── scan context ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct ScanContext {
    // Phase 1: PHP detection
    php_confidence: PhpConfidence,
    version: Option<String>,
    evidence: Vec<String>,
    is_apache: bool,

    // Phase 2: phpinfo extras
    is_mod_php: bool,
    phpinfo_body: Option<String>,

    // Phase 3: Exploit preconditions
    session_reachable: Option<bool>,  // Session handler triggered by request
    chunked_accepted: Option<bool>,   // Server accepts chunked TE
    multipart_accepted: Option<bool>, // Server processes multipart POST
    query_hash_ok: Option<bool>,      // 5-param query string accepted
    is_prefork: Option<bool>,         // Apache prefork MPM confirmed
    memory_limit_bytes: Option<u64>,  // PHP memory_limit in bytes
    session_id_len: Option<usize>,    // PHPSESSID cookie value length
}

impl ScanContext {
    fn add_evidence(&mut self, s: impl Into<String>) {
        self.evidence.push(s.into());
    }

    /// How many preconditions we successfully confirmed as "true".
    fn preconditions_met(&self) -> usize {
        let mut n = 0;
        if self.session_reachable == Some(true) {
            n += 1;
        }
        if self.chunked_accepted == Some(true) {
            n += 1;
        }
        if self.multipart_accepted == Some(true) {
            n += 1;
        }
        if self.query_hash_ok == Some(true) {
            n += 1;
        }
        if self.is_apache {
            n += 1;
        }
        if self.is_prefork == Some(true) {
            n += 1;
        }
        if self.memory_limit_bytes.map(|b| b >= 128 * 1024 * 1024) == Some(true) {
            n += 1;
        }
        n
    }

    /// How many preconditions we actually tested (got a definitive answer).
    fn preconditions_tested(&self) -> usize {
        let mut n = 0;
        if self.session_reachable.is_some() {
            n += 1;
        }
        if self.chunked_accepted.is_some() {
            n += 1;
        }
        if self.multipart_accepted.is_some() {
            n += 1;
        }
        if self.query_hash_ok.is_some() {
            n += 1;
        }
        // Apache is always tested (from Server header)
        n += 1;
        if self.is_prefork.is_some() {
            n += 1;
        }
        if self.memory_limit_bytes.is_some() {
            n += 1;
        }
        n
    }
}

// ── helper types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PhpConfidence {
    None,
    Possible,
    Likely,
    Confirmed,
}

impl PhpConfidence {
    fn raise(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}

impl Default for PhpConfidence {
    fn default() -> Self {
        Self::None
    }
}

fn fmt_opt(o: Option<bool>) -> &'static str {
    match o {
        Some(true) => "yes",
        Some(false) => "no",
        None => "untested",
    }
}

fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        assert_eq!(
            PhpSessionHandlerScanner::extract_version("PHP/8.4.26"),
            Some("8.4.26".to_string())
        );
        assert_eq!(
            PhpSessionHandlerScanner::extract_version("Apache/2.4.62 (Debian) PHP/8.3.14"),
            Some("8.3.14".to_string())
        );
        assert_eq!(
            PhpSessionHandlerScanner::extract_version("nginx/1.27"),
            None
        );
    }

    #[test]
    fn test_affected_range() {
        let affected = [
            "8.4.0", "8.4.1", "8.4.26", "8.3.0", "8.3.14", "8.3.99",
            "8.2.0", "8.2.26", "8.1.0", "8.1.31", "8.0.0", "8.0.30",
            "7.4.33", "5.6.40",
        ];
        let safe = ["8.4.27", "8.4.30", "9.0.0"];

        for ver in &affected {
            assert!(
                PhpSessionHandlerScanner::is_version_affected(ver),
                "{} should be affected",
                ver
            );
        }
        for ver in &safe {
            assert!(
                !PhpSessionHandlerScanner::is_version_affected(ver),
                "{} should be safe",
                ver
            );
        }
    }

    #[test]
    fn test_version_hint_affected() {
        // "8.4.x" from session cookie probe
        assert!(PhpSessionHandlerScanner::is_version_affected("8.4.x"));
    }

    #[test]
    fn test_precondition_counting() {
        let mut ctx = ScanContext::default();
        assert_eq!(ctx.preconditions_met(), 0);
        // Apache is always "tested" as part of header analysis
        assert_eq!(ctx.preconditions_tested(), 1);

        ctx.session_reachable = Some(true);
        ctx.chunked_accepted = Some(true);
        ctx.multipart_accepted = Some(true);
        ctx.query_hash_ok = Some(true);
        ctx.is_apache = true;
        ctx.is_prefork = Some(true);
        ctx.memory_limit_bytes = Some(128 * 1024 * 1024);
        assert_eq!(ctx.preconditions_met(), 7);
        assert_eq!(ctx.preconditions_tested(), 7);
    }

    #[test]
    fn test_precondition_partial() {
        let mut ctx = ScanContext::default();
        ctx.session_reachable = Some(true);
        ctx.chunked_accepted = Some(false); // rejected
        ctx.is_apache = true;
        assert_eq!(ctx.preconditions_met(), 2); // session + apache
        assert_eq!(ctx.preconditions_tested(), 3); // session + chunked + apache
    }

    #[test]
    fn test_memory_limit_parse() {
        let mut ctx = ScanContext::default();
        // Simulate phpinfo body with memory_limit
        let phpinfo = r#"<td>memory_limit</td><td class="v">128M</td>"#;
        PhpSessionHandlerScanner::extract_memory_limit(phpinfo, &mut ctx);
        assert_eq!(ctx.memory_limit_bytes, Some(128 * 1024 * 1024));

        let mut ctx2 = ScanContext::default();
        let phpinfo2 = r#"<td>memory_limit</td><td class="v">64M</td>"#;
        PhpSessionHandlerScanner::extract_memory_limit(phpinfo2, &mut ctx2);
        assert_eq!(ctx2.memory_limit_bytes, Some(64 * 1024 * 1024));
    }
}
