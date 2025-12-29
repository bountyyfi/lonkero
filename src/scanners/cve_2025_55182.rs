// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CVE-2025-55182 Scanner
 * React Server Components (RSC) Remote Code Execution
 *
 * Critical CVSS 10.0 vulnerability in React/Next.js RSC Flight protocol
 * Also known as "React2Shell"
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

pub struct Cve202555182Scanner {
    http_client: Arc<HttpClient>,
}

impl Cve202555182Scanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for CVE-2025-55182 (React Server Components RCE)
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[CVE-2025-55182] Scanning for React Server Components RCE");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get initial response
        let response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                info!("[CVE-2025-55182] Failed to fetch target: {}", e);
                return Ok((vulnerabilities, 0));
            }
        };

        // Check 0: Check for WAF protection (Cloudflare, AWS WAF, etc.)
        tests_run += 1;
        let waf_protection = is_waf_protected_against_cve(&response, "CVE-2025-55182");
        if let Some(ref waf) = waf_protection {
            info!("[CVE-2025-55182] Target is protected by {}", waf);
        }

        // Check 1: Detect Next.js usage
        tests_run += 1;
        let is_nextjs = self.detect_nextjs(&response);

        // Check 2: Detect React Server Components usage
        tests_run += 1;
        let has_rsc = self.detect_rsc(&response, url).await;

        // Check 3: Try to determine Next.js version
        tests_run += 1;
        let nextjs_version = self.detect_nextjs_version(&response, url).await;

        // Check 4: Check for RSC endpoints
        tests_run += 1;
        let has_rsc_endpoint = self.check_rsc_endpoints(url).await;

        // Determine vulnerability status
        if is_nextjs || has_rsc {
            let (is_vulnerable, version_info) = self.check_vulnerability_status(&nextjs_version);

            if is_vulnerable {
                // Check if WAF protection mitigates the vulnerability
                if let Some(ref waf) = waf_protection {
                    info!("[NOTE] CVE-2025-55182: Vulnerable version detected but protected by {}", waf);

                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "CVE-2025-55182 - React Server Components RCE (WAF Protected)".to_string(),
                        severity: Severity::Info,
                        confidence: Confidence::High,
                        category: "Remote Code Execution".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description: format!(
                            "This application uses React Server Components (RSC) with a potentially vulnerable version, \
                            but is PROTECTED by {}. The WAF has deployed rules that block CVE-2025-55182 exploitation attempts. \
                            While protected at the network layer, upgrading the underlying software is still recommended. {}",
                            waf, version_info
                        ),
                        evidence: Some(format!(
                            "Next.js detected: {}, RSC detected: {}, RSC endpoints: {}, Version: {}, WAF: {}",
                            is_nextjs, has_rsc, has_rsc_endpoint,
                            nextjs_version.as_deref().unwrap_or("unknown"),
                            waf
                        )),
                        cwe: "CWE-502".to_string(),
                        cvss: 0.0, // Mitigated by WAF
                        verified: false,
                        false_positive: false,
                        remediation: format!(
                            "LOW PRIORITY (WAF Protected):\n\
                            Your application is currently protected by {} which blocks CVE-2025-55182 exploitation.\n\
                            \n\
                            However, we recommend upgrading when convenient:\n\
                            1. Upgrade Next.js to: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7\n\
                            2. Upgrade React to: 19.0.1, 19.1.2, or 19.2.1\n\
                            \n\
                            Reference: https://blog.cloudflare.com/cloudflare-waf-proactively-protects-against-react-vulnerability/",
                            waf
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                } else {
                    info!("[ALERT] CVE-2025-55182: Potentially vulnerable Next.js/React detected!");

                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "CVE-2025-55182 - React Server Components RCE".to_string(),
                        severity: Severity::Critical,
                        confidence: if nextjs_version.is_some() { Confidence::High } else { Confidence::Medium },
                        category: "Remote Code Execution".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description: format!(
                            "CRITICAL: This application appears to use React Server Components (RSC) and may be vulnerable to CVE-2025-55182 (\"React2Shell\"). \
                            This is a deserialization vulnerability in the RSC Flight protocol that allows unauthenticated remote code execution. \
                            CVSS Score: 10.0 (Critical). {}",
                            version_info
                        ),
                        evidence: Some(format!(
                            "Next.js detected: {}, RSC detected: {}, RSC endpoints: {}, Version: {}",
                            is_nextjs, has_rsc, has_rsc_endpoint,
                            nextjs_version.as_deref().unwrap_or("unknown")
                        )),
                        cwe: "CWE-502".to_string(),
                        cvss: 10.0,
                        verified: false,
                        false_positive: false,
                        remediation: format!(
                            "IMMEDIATE ACTION REQUIRED:\n\
                            1. Upgrade Next.js to patched version: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7\n\
                            2. Upgrade React to patched version: 19.0.1, 19.1.2, or 19.2.1\n\
                            3. If on 14.3 canary, downgrade to 14.x stable or 14.3.0-canary.76\n\
                            4. Enable WAF protection (Cloudflare, AWS, Vercel WAF have deployed rules)\n\
                            5. Monitor for suspicious requests to Server Function endpoints\n\
                            \n\
                            Vulnerable versions:\n\
                            - React: 19.0, 19.1.0, 19.1.1, 19.2.0\n\
                            - Next.js: >=14.3.0-canary.77, >=15 (unpatched), >=16 (unpatched)\n\
                            \n\
                            Reference: https://vercel.com/changelog/cve-2025-55182"
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            } else if has_rsc || has_rsc_endpoint {
                // RSC detected but likely patched or version unknown
                info!("[NOTE] RSC detected but version appears patched or unknown");

                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "CVE-2025-55182 - React Server Components (Verify Version)".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    category: "Remote Code Execution".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!(
                        "This application uses React Server Components (RSC). Verify that your Next.js/React versions \
                        are patched against CVE-2025-55182. {}",
                        version_info
                    ),
                    evidence: Some(format!(
                        "RSC indicators detected. Version: {}",
                        nextjs_version.as_deref().unwrap_or("could not be determined")
                    )),
                    cwe: "CWE-502".to_string(),
                    cvss: 5.0,
                    verified: false,
                    false_positive: false,
                    remediation: "Verify your Next.js version is one of: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\
                        Verify your React version is one of: 19.0.1, 19.1.2, 19.2.1\n\
                        If not, upgrade immediately.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        info!("[SUCCESS] [CVE-2025-55182] Completed {} tests, found {} issues",
            tests_run, vulnerabilities.len());

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

        nextjs_indicators.iter().any(|indicator| body.contains(indicator))
    }

    /// Detect React Server Components usage
    async fn detect_rsc(&self, response: &crate::http_client::HttpResponse, _url: &str) -> bool {
        let body = &response.body;

        // RSC indicators
        let rsc_indicators = [
            "__next_f",           // Next.js RSC Flight data
            "self.__next_f",      // RSC hydration
            "react-server",       // React server module
            "use server",         // Server actions directive
            "rsc=",               // RSC query parameter
            "Flight",             // Flight protocol references
            "createFromFetch",    // RSC fetch creation
            "__RSC_MANIFEST",     // RSC manifest
        ];

        rsc_indicators.iter().any(|indicator| body.contains(indicator))
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

    /// Check for RSC-specific endpoints
    async fn check_rsc_endpoints(&self, url: &str) -> bool {
        let base_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let origin = format!(
            "{}://{}",
            base_url.scheme(),
            base_url.host_str().unwrap_or("")
        );

        // RSC endpoints to check
        let rsc_paths = [
            "/?_rsc=1",
            "/_rsc",
            "/?__flight__=1",
        ];

        for path in &rsc_paths {
            let test_url = format!("{}{}", origin, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                // RSC responses typically have specific content types or Flight data
                let is_rsc_response = response.headers.iter().any(|(k, v)| {
                    (k.to_lowercase() == "content-type" && v.contains("text/x-component")) ||
                    (k.to_lowercase() == "content-type" && v.contains("application/octet-stream"))
                }) || response.body.starts_with("0:") || response.body.contains("$");

                if is_rsc_response {
                    return true;
                }
            }
        }

        false
    }

    /// Check if detected version is vulnerable
    fn check_vulnerability_status(&self, version: &Option<String>) -> (bool, String) {
        let Some(ver) = version else {
            return (true, "Version could not be determined - assume vulnerable until verified.".to_string());
        };

        // Parse version
        let parts: Vec<&str> = ver.split('.').collect();
        if parts.len() < 2 {
            return (true, format!("Invalid version format: {} - assume vulnerable.", ver));
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        // Patched versions for Next.js:
        // 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7
        let is_patched = match (major, minor) {
            (16, 0) => patch >= 7,
            (15, 5) => patch >= 7,
            (15, 4) => patch >= 8,
            (15, 3) => patch >= 6,
            (15, 2) => patch >= 6,
            (15, 1) => patch >= 9,
            (15, 0) => patch >= 5,
            (14, _) => true, // 14.x stable is not affected (only 14.3 canary)
            (m, _) if m < 14 => true, // Versions before 14 don't have RSC
            _ => false,
        };

        if is_patched {
            (false, format!("Detected version {} appears to be patched.", ver))
        } else {
            (true, format!("Detected version {} is VULNERABLE! Immediate upgrade required.", ver))
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
        let scanner = Cve202555182Scanner::new(Arc::new(
            HttpClient::with_config(30, 2, false, false, 100, 10).unwrap()
        ));

        // Vulnerable versions
        assert!(scanner.check_vulnerability_status(&Some("15.0.0".to_string())).0);
        assert!(scanner.check_vulnerability_status(&Some("15.1.0".to_string())).0);
        assert!(scanner.check_vulnerability_status(&Some("15.5.0".to_string())).0);
        assert!(scanner.check_vulnerability_status(&Some("16.0.0".to_string())).0);
    }

    #[test]
    fn test_version_check_patched() {
        let scanner = Cve202555182Scanner::new(Arc::new(
            HttpClient::with_config(30, 2, false, false, 100, 10).unwrap()
        ));

        // Patched versions
        assert!(!scanner.check_vulnerability_status(&Some("15.0.5".to_string())).0);
        assert!(!scanner.check_vulnerability_status(&Some("15.1.9".to_string())).0);
        assert!(!scanner.check_vulnerability_status(&Some("15.5.7".to_string())).0);
        assert!(!scanner.check_vulnerability_status(&Some("16.0.7".to_string())).0);
    }
}
