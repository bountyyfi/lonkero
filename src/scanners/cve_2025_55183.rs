// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CVE-2025-55183 Scanner
 * React Server Components Source Code Exposure
 *
 * Medium severity vulnerability (CVSS 5.3) that can leak server-side source code
 * when Server Functions accept arguments that undergo string coercion without validation.
 *
 * Reference: https://nextjs.org/blog/security-update-2025-12-11
 * Reference: https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::cdn_detector::is_waf_protected_against_cve;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::info;

pub struct Cve202555183Scanner {
    http_client: Arc<HttpClient>,
}

impl Cve202555183Scanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for CVE-2025-55183 (React Server Components Source Code Exposure)
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[CVE-2025-55183] Scanning for RSC Source Code Exposure vulnerability");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get initial response
        let response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                info!("[CVE-2025-55183] Failed to fetch target: {}", e);
                return Ok((vulnerabilities, 0));
            }
        };

        // Check 0: Check for WAF protection (Cloudflare, AWS WAF, etc.)
        tests_run += 1;
        let waf_protection = is_waf_protected_against_cve(&response, "CVE-2025-55183");
        if let Some(ref waf) = waf_protection {
            info!("[CVE-2025-55183] Target is protected by {}", waf);
        }

        // Check 1: Detect Next.js usage
        tests_run += 1;
        let is_nextjs = self.detect_nextjs(&response);

        // Check 2: Detect React Server Components usage
        tests_run += 1;
        let has_rsc = self.detect_rsc(&response);

        // Check 3: Try to determine Next.js version
        tests_run += 1;
        let nextjs_version = self.detect_nextjs_version(&response, url).await;

        // Check 4: Check for Server Actions (required for this vulnerability)
        tests_run += 1;
        let has_server_actions = self.detect_server_actions(&response, url).await;

        // Determine vulnerability status
        // Note: CVE-2025-55183 only affects Next.js 15.x+ (not 13.x or 14.x)
        if (is_nextjs || has_rsc) && self.is_version_15_or_higher(&nextjs_version) {
            let (is_vulnerable, version_info) = self.check_vulnerability_status(&nextjs_version);

            if is_vulnerable {
                // Check if WAF protection mitigates the vulnerability
                if let Some(ref waf) = waf_protection {
                    info!(
                        "[NOTE] CVE-2025-55183: Vulnerable version detected but protected by {}",
                        waf
                    );

                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "CVE-2025-55183 - RSC Source Code Exposure (WAF Protected)".to_string(),
                        severity: Severity::Info,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description: format!(
                            "This application uses React Server Components (RSC) with a potentially vulnerable version, \
                            but is PROTECTED by {}. The WAF has deployed rules that block CVE-2025-55183 exploitation attempts. \
                            While protected at the network layer, upgrading the underlying software is still recommended. {}",
                            waf, version_info
                        ),
                        evidence: Some(format!(
                            "Next.js detected: {}, RSC detected: {}, Server Actions: {}, Version: {}, WAF: {}",
                            is_nextjs, has_rsc, has_server_actions,
                            nextjs_version.as_deref().unwrap_or("unknown"),
                            waf
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 0.0, // Mitigated by WAF
                        verified: false,
                        false_positive: false,
                        remediation: format!(
                            "LOW PRIORITY (WAF Protected):\n\
                            Your application is currently protected by {} which blocks CVE-2025-55183 exploitation.\n\
                            \n\
                            However, we recommend upgrading when convenient:\n\
                            - Next.js 15.0.x -> 15.0.7\n\
                            - Next.js 15.1.x -> 15.1.11\n\
                            - Next.js 15.2.x -> 15.2.8\n\
                            - Next.js 15.3.x -> 15.3.8\n\
                            - Next.js 15.4.x -> 15.4.10\n\
                            - Next.js 15.5.x -> 15.5.9\n\
                            - Next.js 16.0.x -> 16.0.10\n\
                            \n\
                            Reference: https://nextjs.org/blog/security-update-2025-12-11",
                            waf
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                } else {
                    info!("[ALERT] CVE-2025-55183: Potentially vulnerable Next.js/React detected!");

                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "CVE-2025-55183 - RSC Source Code Exposure".to_string(),
                        severity: Severity::Medium,
                        confidence: if nextjs_version.is_some() { Confidence::High } else { Confidence::Medium },
                        category: "Information Disclosure".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description: format!(
                            "This application uses React Server Components (RSC) and may be vulnerable to CVE-2025-55183. \
                            A malicious HTTP request can be crafted to return the compiled source code of Server Actions. \
                            This could reveal business logic but would not expose secrets unless they were hardcoded. \
                            CVSS Score: 5.3 (Medium). {}",
                            version_info
                        ),
                        evidence: Some(format!(
                            "Next.js detected: {}, RSC detected: {}, Server Actions: {}, Version: {}",
                            is_nextjs, has_rsc, has_server_actions,
                            nextjs_version.as_deref().unwrap_or("unknown")
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: false,
                        false_positive: false,
                        remediation: format!(
                            "ACTION REQUIRED:\n\
                            1. Upgrade Next.js to patched version:\n\
                               - Next.js 15.0.x -> 15.0.7\n\
                               - Next.js 15.1.x -> 15.1.11\n\
                               - Next.js 15.2.x -> 15.2.8\n\
                               - Next.js 15.3.x -> 15.3.8\n\
                               - Next.js 15.4.x -> 15.4.10\n\
                               - Next.js 15.5.x -> 15.5.9\n\
                               - Next.js 16.0.x -> 16.0.10\n\
                            2. Enable WAF protection (Cloudflare, Vercel WAF have deployed rules)\n\
                            3. Avoid hardcoding secrets in Server Actions\n\
                            4. Review Server Actions for sensitive business logic\n\
                            \n\
                            Note: Next.js 13.x and 14.x are NOT affected by this vulnerability.\n\
                            \n\
                            Reference: https://nextjs.org/blog/security-update-2025-12-11"
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }
            } else if has_rsc || has_server_actions {
                // RSC detected but version appears patched
                info!("[NOTE] RSC detected but version appears patched for CVE-2025-55183");
            }
        }

        info!(
            "[SUCCESS] [CVE-2025-55183] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if site uses Next.js
    fn detect_nextjs(&self, response: &crate::http_client::HttpResponse) -> bool {
        let body = &response.body;
        let headers = &response.headers;

        // Check headers
        if headers.iter().any(|(k, v)| {
            k.to_lowercase() == "x-powered-by" && v.to_lowercase().contains("next.js")
        }) {
            return true;
        }

        // Check for Next.js indicators in HTML
        let nextjs_indicators = [
            "_next/static",
            "__next",
            "__NEXT_DATA__",
            "/_next/",
            "next/dist",
            "nextjs",
            "_buildManifest.js",
            "_ssgManifest.js",
        ];

        nextjs_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    /// Detect React Server Components usage
    fn detect_rsc(&self, response: &crate::http_client::HttpResponse) -> bool {
        let body = &response.body;

        // RSC indicators
        let rsc_indicators = [
            "__next_f",        // Next.js RSC Flight data
            "self.__next_f",   // RSC hydration
            "react-server",    // React server module
            "rsc=",            // RSC query parameter
            "Flight",          // Flight protocol references
            "createFromFetch", // RSC fetch creation
            "__RSC_MANIFEST",  // RSC manifest
        ];

        rsc_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    /// Detect Server Actions usage (specific to CVE-2025-55183)
    async fn detect_server_actions(
        &self,
        response: &crate::http_client::HttpResponse,
        _url: &str,
    ) -> bool {
        let body = &response.body;

        // Server Actions indicators
        let server_action_indicators = [
            "use server",      // Server actions directive
            "$$ACTION",        // Server action reference
            "formAction",      // Form actions
            "serverActions",   // Server actions config
            "__next_action__", // Next.js action marker
        ];

        server_action_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    /// Check if version is 15.x or higher (CVE-2025-55183 only affects 15+)
    fn is_version_15_or_higher(&self, version: &Option<String>) -> bool {
        let Some(ver) = version else {
            // If we can't determine version, assume it could be affected
            return true;
        };

        let parts: Vec<&str> = ver.split('.').collect();
        if parts.is_empty() {
            return true;
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        major >= 15
    }

    /// Try to detect Next.js version
    async fn detect_nextjs_version(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
    ) -> Option<String> {
        let body = &response.body;

        // Method 1: Check for version in __NEXT_DATA__
        let next_data_regex = Regex::new(r#"__NEXT_DATA__.*?"version"\s*:\s*"([^"]+)"#).ok()?;
        if let Some(caps) = next_data_regex.captures(body) {
            if let Some(version) = caps.get(1) {
                return Some(version.as_str().to_string());
            }
        }

        // Method 2: Check build manifest for version hints
        let version_regex = Regex::new(r#"next[/-](\d+\.\d+\.\d+)"#).ok()?;
        if let Some(caps) = version_regex.captures(body) {
            if let Some(version) = caps.get(1) {
                return Some(version.as_str().to_string());
            }
        }

        // Method 3: Try to fetch _next/static chunks and check for version
        let base_url = url::Url::parse(url).ok()?;
        let build_id_url = format!(
            "{}://{}/_next/static/chunks/webpack.js",
            base_url.scheme(),
            base_url.host_str()?
        );

        if let Ok(webpack_resp) = self.http_client.get(&build_id_url).await {
            if let Some(caps) = version_regex.captures(&webpack_resp.body) {
                if let Some(version) = caps.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }

        None
    }

    /// Check if detected version is vulnerable to CVE-2025-55183
    fn check_vulnerability_status(&self, version: &Option<String>) -> (bool, String) {
        let Some(ver) = version else {
            return (
                true,
                "Version could not be determined - assume vulnerable until verified.".to_string(),
            );
        };

        // Parse version
        let parts: Vec<&str> = ver.split('.').collect();
        if parts.len() < 2 {
            return (
                true,
                format!("Invalid version format: {} - assume vulnerable.", ver),
            );
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        // CVE-2025-55183 does NOT affect Next.js 13.x or 14.x
        if major < 15 {
            return (
                false,
                format!(
                    "Version {} is not affected by CVE-2025-55183 (only affects 15.x+).",
                    ver
                ),
            );
        }

        // Patched versions for Next.js (CVE-2025-55183):
        // 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9, 16.0.10
        let is_patched = match (major, minor) {
            (16, 0) => patch >= 10,
            (15, 5) => patch >= 9,
            (15, 4) => patch >= 10,
            (15, 3) => patch >= 8,
            (15, 2) => patch >= 8,
            (15, 1) => patch >= 11,
            (15, 0) => patch >= 7,
            (m, _) if m > 16 => true, // Future versions assumed patched
            _ => false,
        };

        if is_patched {
            (
                false,
                format!(
                    "Detected version {} appears to be patched for CVE-2025-55183.",
                    ver
                ),
            )
        } else {
            (
                true,
                format!(
                    "Detected version {} is VULNERABLE to CVE-2025-55183! Upgrade required.",
                    ver
                ),
            )
        }
    }
}

fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_check_vulnerable() {
        let scanner = Cve202555183Scanner::new(Arc::new(
            HttpClient::with_config(30, 2, false, false, 100, 10).unwrap(),
        ));

        // Vulnerable versions (15.x unpatched)
        assert!(
            scanner
                .check_vulnerability_status(&Some("15.0.0".to_string()))
                .0
        );
        assert!(
            scanner
                .check_vulnerability_status(&Some("15.1.0".to_string()))
                .0
        );
        assert!(
            scanner
                .check_vulnerability_status(&Some("15.5.0".to_string()))
                .0
        );
        assert!(
            scanner
                .check_vulnerability_status(&Some("16.0.0".to_string()))
                .0
        );
    }

    #[test]
    fn test_version_check_patched() {
        let scanner = Cve202555183Scanner::new(Arc::new(
            HttpClient::with_config(30, 2, false, false, 100, 10).unwrap(),
        ));

        // Patched versions
        assert!(
            !scanner
                .check_vulnerability_status(&Some("15.0.7".to_string()))
                .0
        );
        assert!(
            !scanner
                .check_vulnerability_status(&Some("15.1.11".to_string()))
                .0
        );
        assert!(
            !scanner
                .check_vulnerability_status(&Some("15.5.9".to_string()))
                .0
        );
        assert!(
            !scanner
                .check_vulnerability_status(&Some("16.0.10".to_string()))
                .0
        );
    }

    #[test]
    fn test_version_13_14_not_affected() {
        let scanner = Cve202555183Scanner::new(Arc::new(
            HttpClient::with_config(30, 2, false, false, 100, 10).unwrap(),
        ));

        // 13.x and 14.x are not affected
        assert!(
            !scanner
                .check_vulnerability_status(&Some("13.5.0".to_string()))
                .0
        );
        assert!(
            !scanner
                .check_vulnerability_status(&Some("14.2.0".to_string()))
                .0
        );
    }
}
