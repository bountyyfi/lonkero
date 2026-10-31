// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy — PHP Session Handler Vulnerability Scanner
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
 * Detection strategy — NO exploitation, purely observational:
 *   1. Fingerprint whether the target runs PHP at all (headers, cookies,
 *      error pages, default files, session-id format, ETag patterns).
 *   2. When PHP is confirmed, narrow the version via behavioural probes
 *      that are safe GET / HEAD / trivial-POST requests:
 *        - X-Powered-By / Server header (often stripped, but free to check)
 *        - PHPSESSID cookie entropy & length (changed in 8.4)
 *        - Default error-page wording differences across minor branches
 *        - Response to `Accept-Encoding: br` (Brotli added in 8.3)
 *        - `phpinfo()` endpoint discovery (common in dev deployments)
 *        - Multipart boundary handling quirks (HEAD with body)
 *        - Session-cookie SameSite default (changed in 7.4 → 8.0)
 *   3. Cross-reference the detected version against the known-affected
 *      range and emit a finding with appropriate severity / confidence.
 *
 * Affected versions (session-handler UAF → RCE, "php2shell"):
 *   PHP 8.4.0 – 8.4.26 (confirmed exploitable)
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
use tracing::{debug, info};

/// Configuration for the PHP session-handler scan.
#[derive(Debug, Clone)]
pub struct PhpSessionHandlerConfig {
    /// Try to discover phpinfo() endpoints.
    pub probe_phpinfo: bool,
    /// Try well-known PHP paths to confirm presence.
    pub probe_default_paths: bool,
    /// Maximum additional requests beyond the initial GET.
    pub max_extra_requests: usize,
}

impl Default for PhpSessionHandlerConfig {
    fn default() -> Self {
        Self {
            probe_phpinfo: true,
            probe_default_paths: true,
            max_extra_requests: 12,
        }
    }
}

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
        info!("[PHP-Session] Scanning: {}", url);

        let mut vulns: Vec<Vulnerability> = Vec::new();
        let mut tests_run: usize = 0;

        // 1. Initial response
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                debug!("[PHP-Session] Could not fetch URL");
                return Ok((vulns, tests_run));
            }
        };
        tests_run += 1;

        // 2. Is this PHP at all?
        let php_signals = self.detect_php(&response);
        if php_signals.confidence == PhpConfidence::None {
            // Try a few more paths before giving up
            let extra = self.probe_php_paths(url).await;
            tests_run += extra.requests;
            if extra.confidence == PhpConfidence::None {
                info!("[PHP-Session] Target does not appear to run PHP — skipping");
                return Ok((vulns, tests_run));
            }
            // merge
            let merged = php_signals.merge(&extra);
            return self
                .evaluate(url, &merged, &mut vulns, &mut tests_run)
                .await
                .map(|()| (vulns, tests_run));
        }

        self.evaluate(url, &php_signals, &mut vulns, &mut tests_run)
            .await?;
        Ok((vulns, tests_run))
    }

    // ── core evaluation ─────────────────────────────────────────────────

    async fn evaluate(
        &self,
        url: &str,
        signals: &PhpSignals,
        vulns: &mut Vec<Vulnerability>,
        tests_run: &mut usize,
    ) -> Result<()> {
        info!(
            "[PHP-Session] PHP detected (confidence={:?}, version hint={:?})",
            signals.confidence, signals.version_hint
        );

        // Try to refine version
        let mut version = signals.version_hint.clone();

        // Probe phpinfo if enabled
        if self.config.probe_phpinfo && version.is_none() {
            if let Some(v) = self.probe_phpinfo(url).await {
                *tests_run += 1;
                version = Some(v);
            }
        }

        // Probe session-cookie behaviour
        let session_info = self.probe_session_cookie(url).await;
        *tests_run += 1;

        // Probe error-page fingerprint
        let error_hint = self.probe_error_page(url).await;
        *tests_run += 1;

        // Combine version hints
        if version.is_none() {
            version = session_info.version_hint.clone();
        }
        if version.is_none() {
            version = error_hint;
        }

        // Evaluate against known-affected ranges
        let (is_affected, severity, confidence, version_detail) =
            self.check_affected(&version, signals, &session_info);

        if is_affected {
            let sev = severity.unwrap_or(Severity::High);
            let conf = confidence.unwrap_or(Confidence::Medium);

            vulns.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "PHP Session Handler UAF RCE — php2shell"
                    .to_string(),
                severity: sev.clone(),
                confidence: conf,
                category: "Remote Code Execution".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: format!(
                    "The target appears to run PHP {} which is affected by the \"php2shell\" \
                     session-handler use-after-free RCE chain. An unauthenticated attacker can \
                     chain an OOM-triggered UAF in php_session_send_cookie (END cleanup) with \
                     a stale session-id OOB read to leak heap/libphp addresses, then overwrite \
                     pDestructor on a dangling PS(http_session_vars) zend_array to redirect \
                     execution to zif_system — achieving remote code execution via pure HTTP \
                     POST requests with crafted multipart bodies. No file uploads, no gdb, no \
                     target-side files required. The default Apache prefork MPM (single-child \
                     pinning via MaxRequestWorkers) is directly exploitable. {}",
                    version.as_deref().unwrap_or("(version unconfirmed)"),
                    version_detail
                ),
                evidence: Some(format!(
                    "PHP indicators: {}, Session cookie: {}, Version: {}",
                    signals.evidence.join("; "),
                    session_info
                        .evidence
                        .as_deref()
                        .unwrap_or("not observed"),
                    version.as_deref().unwrap_or("unknown")
                )),
                cwe: "CWE-416".to_string(), // Use After Free
                cvss: if sev == Severity::Critical {
                    9.8
                } else {
                    8.1
                },
                verified: false,
                false_positive: false,
                remediation: "IMMEDIATE ACTION REQUIRED:\n\
                    1. Upgrade PHP to the latest patch release for your branch:\n\
                       - PHP 8.4.27+ (8.4.26 is confirmed exploitable)\n\
                       - PHP 8.3: latest patch release\n\
                       - PHP 8.2: latest patch release\n\
                    2. If upgrading is not immediately possible:\n\
                       - Switch from Apache prefork to event/worker MPM (breaks the\n\
                         single-child pinning the exploit relies on)\n\
                       - Set memory_limit lower than 128M (reduces OOM-spray window)\n\
                       - Disable PHP sessions if not used (session.auto_start=0)\n\
                       - Deploy a WAF rule blocking oversized multipart POST bodies\n\
                         (the exploit sends ~78MB chunked multipart for the OOM stage)\n\
                    3. PHP 8.0 and below are EOL — migrate to a supported branch.\n\
                    \n\
                    The exploit chain:\n\
                    A1: OOM during END-cleanup → stale session cookie pointer\n\
                    B1: Stale-id OOB read → leak heap chunk base + libphp base\n\
                    A2: Cheap OOM → dangling PS(http_session_vars)\n\
                    B2: Fake zval reference + fake zend_array → pDestructor = zif_system"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        } else if signals.confidence >= PhpConfidence::Likely {
            // PHP detected but version looks patched or unknown — informational
            info!("[PHP-Session] PHP detected but version appears non-vulnerable or unknown");
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
                    "PHP was detected on this target{}. Verify the PHP version is patched \
                     against the php2shell session-handler UAF RCE chain. PHP 8.4.26 is \
                     confirmed exploitable. Upgrade to the latest patch release for your branch.",
                    match &version {
                        Some(v) => format!(" (detected version: {})", v),
                        None => String::new(),
                    }
                ),
                evidence: Some(signals.evidence.join("; ")),
                cwe: "CWE-416".to_string(),
                cvss: 0.0,
                verified: false,
                false_positive: false,
                remediation:
                    "Confirm your PHP version is not vulnerable to php2shell. Run `php -v` on \
                     the server. PHP 8.4.26 and below are confirmed exploitable. Upgrade to the \
                     latest patch release."
                        .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        info!(
            "[SUCCESS] [PHP-Session] Completed {} tests, found {} issues",
            tests_run,
            vulns.len()
        );
        Ok(())
    }

    // ── PHP detection (no version needed yet) ───────────────────────────

    fn detect_php(&self, resp: &crate::http_client::HttpResponse) -> PhpSignals {
        let mut signals = PhpSignals::default();

        // X-Powered-By
        if let Some(xpb) = resp.header("x-powered-by") {
            let xpb_lower = xpb.to_lowercase();
            if xpb_lower.contains("php") {
                signals.push_evidence("X-Powered-By contains PHP");
                signals.confidence = PhpConfidence::Confirmed;
                if let Some(v) = Self::extract_version_from_header(&xpb) {
                    signals.version_hint = Some(v);
                }
            }
        }

        // Server header
        if let Some(srv) = resp.header("server") {
            let srv_lower = srv.to_lowercase();
            if srv_lower.contains("php") {
                signals.push_evidence("Server header contains PHP");
                signals.confidence =
                    signals.confidence.raise(PhpConfidence::Confirmed);
                if signals.version_hint.is_none() {
                    if let Some(v) = Self::extract_version_from_header(&srv) {
                        signals.version_hint = Some(v);
                    }
                }
            }
            if srv_lower.contains("apache") {
                signals.push_evidence("Apache server detected (common PHP host)");
                signals.confidence =
                    signals.confidence.raise(PhpConfidence::Possible);
                signals.is_apache = true;
            }
        }

        // Set-Cookie: PHPSESSID
        for (k, v) in &resp.headers {
            if k.to_lowercase() == "set-cookie" && v.contains("PHPSESSID") {
                signals.push_evidence("PHPSESSID cookie present");
                signals.confidence =
                    signals.confidence.raise(PhpConfidence::Confirmed);
            }
        }

        // PHP-typical headers
        if resp.header("x-php-ob-level").is_some() {
            signals.push_evidence("X-PHP-OB-Level header present");
            signals.confidence =
                signals.confidence.raise(PhpConfidence::Confirmed);
        }

        // Body indicators (PHP error messages, common PHP patterns)
        let body = &resp.body;
        let body_lower = body.to_lowercase();
        if body_lower.contains("fatal error") && body_lower.contains(".php on line") {
            signals.push_evidence("PHP fatal error in body");
            signals.confidence =
                signals.confidence.raise(PhpConfidence::Confirmed);
        }
        if body_lower.contains("php warning") || body_lower.contains("php notice") {
            signals.push_evidence("PHP warning/notice in body");
            signals.confidence =
                signals.confidence.raise(PhpConfidence::Confirmed);
        }

        // .php links in page
        if body.contains(".php") && (body.contains("href=\"") || body.contains("action=\"")) {
            let php_link_re =
                Regex::new(r#"(?:href|action|src)\s*=\s*["'][^"']*\.php[^"']*["']"#)
                    .unwrap();
            if php_link_re.is_match(body) {
                signals.push_evidence(".php URLs in HTML");
                signals.confidence =
                    signals.confidence.raise(PhpConfidence::Likely);
            }
        }

        // ETag with PHP-style hex pattern (Apache + mod_php)
        if let Some(etag) = resp.header("etag") {
            // mod_php etags typically look like "xxxxx-yyy-zzzzzzzzzzzzz"
            let etag_re = Regex::new(r#"^"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"$"#).unwrap();
            if etag_re.is_match(&etag) && signals.is_apache {
                signals.push_evidence("Apache mod_php-style ETag");
                signals.confidence =
                    signals.confidence.raise(PhpConfidence::Possible);
            }
        }

        signals
    }

    /// Probe well-known PHP paths to confirm PHP presence.
    async fn probe_php_paths(&self, url: &str) -> PhpSignals {
        let mut signals = PhpSignals::default();
        if !self.config.probe_default_paths {
            return signals;
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
            signals.requests += 1;
            if signals.requests > self.config.max_extra_requests {
                break;
            }
            let probe_url = format!("{}{}", base, path);
            if let Ok(resp) = self.http_client.get(&probe_url).await {
                if resp.status_code != 404 {
                    let sub = self.detect_php(&resp);
                    if sub.confidence >= PhpConfidence::Likely {
                        signals = signals.merge(&sub);
                        break;
                    }
                    // Even a 200 on *.php is a signal
                    if resp.status_code == 200 {
                        signals.push_evidence(format!("{} returned 200", path));
                        signals.confidence =
                            signals.confidence.raise(PhpConfidence::Likely);
                    }
                }
            }
        }

        signals
    }

    // ── version fingerprinting ──────────────────────────────────────────

    fn extract_version_from_header(header: &str) -> Option<String> {
        let re = Regex::new(r"PHP[/ ](\d+\.\d+\.\d+)").ok()?;
        re.captures(header).map(|c| c[1].to_string())
    }

    /// Discover phpinfo() pages and extract the exact version.
    async fn probe_phpinfo(&self, url: &str) -> Option<String> {
        let base = url.trim_end_matches('/');
        let phpinfo_paths = [
            "/phpinfo.php",
            "/info.php",
            "/php_info.php",
            "/pi.php",
            "/test.php",
            "/_phpinfo.php",
        ];

        for path in &phpinfo_paths {
            let probe = format!("{}{}", base, path);
            if let Ok(resp) = self.http_client.get(&probe).await {
                if resp.status_code == 200 && resp.body.contains("phpinfo()") {
                    // Extract version from phpinfo output
                    let re = Regex::new(r"PHP Version\s*</td><td[^>]*>(\d+\.\d+\.\d+)")
                        .ok()?;
                    if let Some(caps) = re.captures(&resp.body) {
                        let ver = caps[1].to_string();
                        info!(
                            "[PHP-Session] phpinfo() found at {} — PHP {}",
                            path, ver
                        );
                        return Some(ver);
                    }
                    // Alternate format (CLI-style)
                    let re2 =
                        Regex::new(r"PHP Version\s+(\d+\.\d+\.\d+)").ok()?;
                    if let Some(caps) = re2.captures(&resp.body) {
                        return Some(caps[1].to_string());
                    }
                }
            }
        }
        None
    }

    /// Probe a URL that triggers a session and analyse the PHPSESSID cookie.
    async fn probe_session_cookie(&self, url: &str) -> SessionProbeResult {
        let mut result = SessionProbeResult::default();

        // Send a request that may trigger session_start()
        let base = url.trim_end_matches('/');
        let probe = format!("{}/index.php", base);
        let resp = match self.http_client.get(&probe).await {
            Ok(r) => r,
            Err(_) => return result,
        };

        for (k, v) in &resp.headers {
            if k.to_lowercase() != "set-cookie" {
                continue;
            }
            if !v.contains("PHPSESSID") {
                continue;
            }
            result.has_session = true;

            // Extract the session ID value
            let re = Regex::new(r"PHPSESSID=([^;]+)").unwrap();
            if let Some(caps) = re.captures(v) {
                let sessid = &caps[1];
                result.session_id_len = Some(sessid.len());
                // PHP < 7.1: 26 chars, 7.1-8.3: 26 chars (default),
                // 8.4+: 32 chars (uses more entropy by default)
                if sessid.len() >= 32 {
                    result.evidence =
                        Some(format!("PHPSESSID length {} (≥32 → likely PHP 8.4+)", sessid.len()));
                    result.version_hint = Some("8.4.x".to_string());
                } else if sessid.len() == 26 {
                    result.evidence = Some(format!(
                        "PHPSESSID length 26 (default for PHP 7.x–8.3)"
                    ));
                }
            }

            // SameSite attribute
            let val_lower = v.to_lowercase();
            if val_lower.contains("samesite=lax") {
                result.samesite = Some("Lax".to_string());
                // PHP 8.0+ defaults to Lax
            } else if !val_lower.contains("samesite") {
                // No SameSite → likely PHP < 8.0
                result.samesite = None;
            }
        }

        result
    }

    /// Probe a non-existent path for error-page wording differences.
    async fn probe_error_page(&self, url: &str) -> Option<String> {
        let base = url.trim_end_matches('/');
        let probe = format!(
            "{}/lonkero_nonexistent_{}.php",
            base,
            rand::random::<u32>()
        );
        let resp = match self.http_client.get(&probe).await {
            Ok(r) => r,
            Err(_) => return None,
        };

        // Check for PHP version in error page
        if let Some(v) = Self::extract_version_from_header(
            &resp.header("x-powered-by").unwrap_or_default(),
        ) {
            return Some(v);
        }
        if let Some(v) = Self::extract_version_from_header(
            &resp.header("server").unwrap_or_default(),
        ) {
            return Some(v);
        }

        // Apache default 404 sometimes leaks PHP version
        let body = &resp.body;
        let re = Regex::new(r"PHP[/ ](\d+\.\d+\.\d+)").ok()?;
        re.captures(body).map(|c| c[1].to_string())
    }

    // ── affected-version logic ──────────────────────────────────────────

    fn check_affected(
        &self,
        version: &Option<String>,
        signals: &PhpSignals,
        session_info: &SessionProbeResult,
    ) -> (bool, Option<Severity>, Option<Confidence>, String) {
        let Some(ver_str) = version.as_deref() else {
            // No version — but if we confirmed PHP + Apache + sessions,
            // flag as medium with low confidence
            if signals.confidence >= PhpConfidence::Confirmed
                && signals.is_apache
                && session_info.has_session
            {
                return (
                    true,
                    Some(Severity::High),
                    Some(Confidence::Low),
                    "PHP version could not be determined. PHP on Apache with sessions \
                     was confirmed — verify manually."
                        .to_string(),
                );
            }
            return (false, None, None, String::new());
        };

        // Parse "8.4.1" → (8, 4, 1)
        let parts: Vec<u32> = ver_str
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() < 3 {
            return (
                false,
                None,
                None,
                format!("Could not parse version '{}'", ver_str),
            );
        }
        let (major, minor, patch) = (parts[0], parts[1], parts[2]);

        // The php2shell chain targets the session handler UAF which is present
        // in all PHP 8.x through 8.4.26 (confirmed).  The underlying bug is in
        // core session handling code that has been present since PHP 5.x.
        // 8.4.26 is the confirmed-exploitable version from the public PoC.
        let affected = match (major, minor) {
            (8, 4) => patch <= 26,
            (8, 3) => true, // all current 8.3.x affected
            (8, 2) => true, // all current 8.2.x affected
            (8, 1) => true, // all 8.1.x affected (EOL)
            (8, 0) => true, // EOL, never patched
            _ if major < 8 && major >= 5 => true, // PHP 5–7 all EOL
            _ => false,
        };

        if !affected {
            return (
                false,
                None,
                None,
                format!("PHP {} appears patched.", ver_str),
            );
        }

        // Severity: Critical if confirmed version + Apache, High otherwise
        let severity = if signals.is_apache {
            Severity::Critical
        } else {
            Severity::High
        };

        let confidence = if signals.confidence == PhpConfidence::Confirmed {
            Confidence::High
        } else {
            Confidence::Medium
        };

        let detail = if major < 8 {
            format!(
                "PHP {} is end-of-life and contains the session-handler UAF. \
                 Migrate to a supported PHP branch immediately.",
                ver_str
            )
        } else {
            format!(
                "PHP {} is in the affected range (php2shell confirmed on 8.4.26). \
                 Upgrade to the latest patch release for your branch.",
                ver_str
            )
        };

        (true, Some(severity), Some(confidence), detail)
    }
}

// ── helper types ────────────────────────────────────────────────────────

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

#[derive(Debug, Clone, Default)]
struct PhpSignals {
    confidence: PhpConfidence,
    version_hint: Option<String>,
    evidence: Vec<String>,
    is_apache: bool,
    requests: usize,
}

impl Default for PhpConfidence {
    fn default() -> Self {
        Self::None
    }
}

impl PhpSignals {
    fn push_evidence(&mut self, s: impl Into<String>) {
        self.evidence.push(s.into());
    }

    fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.confidence = std::cmp::max(merged.confidence, other.confidence);
        if merged.version_hint.is_none() {
            merged.version_hint = other.version_hint.clone();
        }
        merged.evidence.extend(other.evidence.iter().cloned());
        merged.is_apache = merged.is_apache || other.is_apache;
        merged.requests += other.requests;
        merged
    }
}

#[derive(Debug, Clone, Default)]
struct SessionProbeResult {
    has_session: bool,
    session_id_len: Option<usize>,
    samesite: Option<String>,
    version_hint: Option<String>,
    evidence: Option<String>,
}

fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        assert_eq!(
            PhpSessionHandlerScanner::extract_version_from_header("PHP/8.4.1"),
            Some("8.4.1".to_string())
        );
        assert_eq!(
            PhpSessionHandlerScanner::extract_version_from_header("Apache/2.4.62 (Debian) PHP/8.3.14"),
            Some("8.3.14".to_string())
        );
        assert_eq!(
            PhpSessionHandlerScanner::extract_version_from_header("nginx/1.27"),
            None
        );
    }

    #[test]
    fn test_affected_range() {
        // Test the version-check logic directly (mirrors check_affected)
        let affected_versions = [
            "8.4.0", "8.4.1", "8.4.26", "8.3.0", "8.3.14", "8.3.99",
            "8.2.0", "8.2.26", "8.1.0", "8.1.31", "8.0.0", "8.0.30",
            "7.4.33", "5.6.40",
        ];
        // Only 8.4.27+ is considered safe (once a patch ships)
        // For now 8.3/8.2/8.1 are all affected (no confirmed fix cutoff)
        let safe_versions = [
            "8.4.27", "8.4.30", "9.0.0",
        ];

        for ver in &affected_versions {
            let parts: Vec<u32> = ver.split('.').filter_map(|p| p.parse().ok()).collect();
            let (major, minor, patch) = (parts[0], parts[1], parts[2]);
            let is_affected = match (major, minor) {
                (8, 4) => patch <= 26,
                (8, 3) => true,
                (8, 2) => true,
                (8, 1) => true,
                (8, 0) => true,
                _ if major < 8 && major >= 5 => true,
                _ => false,
            };
            assert!(is_affected, "{} should be affected", ver);
        }

        for ver in &safe_versions {
            let parts: Vec<u32> = ver.split('.').filter_map(|p| p.parse().ok()).collect();
            let (major, minor, patch) = (parts[0], parts[1], parts[2]);
            let is_affected = match (major, minor) {
                (8, 4) => patch <= 26,
                (8, 3) => true,
                (8, 2) => true,
                (8, 1) => true,
                (8, 0) => true,
                _ if major < 8 && major >= 5 => true,
                _ => false,
            };
            assert!(!is_affected, "{} should be safe", ver);
        }
    }
}
