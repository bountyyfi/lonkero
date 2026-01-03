// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CDN Detection Module
 * Detects if a target is behind a CDN to skip irrelevant tests
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::HttpResponse;
use tracing::debug;

/// Detects if a response comes from a CDN-protected target
pub fn is_cdn_protected(response: &HttpResponse) -> Option<String> {
    // Cloudflare detection
    if response.header("cf-ray").is_some()
        || response.header("cf-cache-status").is_some()
        || response
            .header("server")
            .map(|s| s.contains("cloudflare"))
            .unwrap_or(false)
    {
        return Some("Cloudflare".to_string());
    }

    // AWS CloudFront
    if response.header("x-amz-cf-id").is_some()
        || response.header("x-amz-cf-pop").is_some()
        || response
            .header("via")
            .map(|s| s.contains("CloudFront"))
            .unwrap_or(false)
    {
        return Some("AWS CloudFront".to_string());
    }

    // Akamai
    if response.header("x-akamai-request-id").is_some()
        || response.header("akamai-grn").is_some()
        || response
            .header("server")
            .map(|s| s.contains("AkamaiGHost"))
            .unwrap_or(false)
    {
        return Some("Akamai".to_string());
    }

    // Fastly
    if response
        .header("x-served-by")
        .map(|s| s.contains("cache"))
        .unwrap_or(false)
        || response.header("x-fastly-request-id").is_some()
        || response.header("fastly-io-info").is_some()
    {
        return Some("Fastly".to_string());
    }

    // Azure Front Door
    if response.header("x-azure-ref").is_some() || response.header("x-fd-healthprobe").is_some() {
        return Some("Azure Front Door".to_string());
    }

    // Google Cloud CDN
    if response
        .header("via")
        .map(|s| s.contains("1.1 google"))
        .unwrap_or(false)
        || response.header("x-goog-generation").is_some()
    {
        return Some("Google Cloud CDN".to_string());
    }

    // Incapsula
    if response
        .header("x-cdn")
        .map(|s| s.contains("Incapsula"))
        .unwrap_or(false)
        || response.header("x-iinfo").is_some()
    {
        return Some("Incapsula".to_string());
    }

    // Sucuri
    if response.header("x-sucuri-id").is_some() || response.header("x-sucuri-cache").is_some() {
        return Some("Sucuri".to_string());
    }

    // StackPath
    if response.header("x-sp-cache-status").is_some() || response.header("x-sp-server").is_some() {
        return Some("StackPath".to_string());
    }

    // KeyCDN
    if response
        .header("server")
        .map(|s| s.contains("keycdn"))
        .unwrap_or(false)
        || response.header("x-keycdn-cache-status").is_some()
    {
        return Some("KeyCDN".to_string());
    }

    // Bunny CDN
    if response.header("x-bunny-cache").is_some()
        || response.header("bunny-cache-status").is_some()
        || response.header("cdn-pullzone").is_some()
        || response
            .header("server")
            .map(|s| s.contains("bunny"))
            .unwrap_or(false)
    {
        return Some("Bunny CDN".to_string());
    }

    // Generic CDN detection via cache headers
    if response.header("x-cache").is_some()
        || response.header("x-cache-status").is_some()
        || response.header("cdn-cache-control").is_some()
    {
        return Some("Generic CDN".to_string());
    }

    None
}

/// Check if a target is protected by a WAF with known rules for a specific CVE
pub fn is_waf_protected_against_cve(response: &HttpResponse, cve_id: &str) -> Option<String> {
    let cdn = is_cdn_protected(response)?;

    // WAFs with known CVE-2025-55182 (React RSC RCE) protection
    // Reference: https://blog.cloudflare.com/cloudflare-waf-proactively-protects-against-react-vulnerability/
    if cve_id == "CVE-2025-55182" {
        match cdn.as_str() {
            "Cloudflare" => {
                // Cloudflare deployed rules on Dec 2, 2025
                // Managed Ruleset: 33aa8a8a948b48b28d40450c5fb92fba
                // Free Ruleset: 2b5d06e34a814a889bee9a0699702280
                debug!("Target is behind Cloudflare WAF - CVE-2025-55182 is blocked by default");
                return Some("Cloudflare WAF (rule deployed Dec 2, 2025)".to_string());
            }
            "AWS CloudFront" => {
                // AWS WAF also has protection rules
                debug!("Target may be protected by AWS WAF - verify WAF rules are enabled");
                return Some("AWS WAF (verify rules are enabled)".to_string());
            }
            "Akamai" => {
                // Akamai App & API Protector has protection
                debug!("Target may be protected by Akamai - verify App & API Protector is enabled");
                return Some("Akamai (verify App & API Protector)".to_string());
            }
            _ => {}
        }
    }

    // WAFs with known CVE-2025-55183 (React RSC Source Code Exposure) protection
    // Reference: https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/
    if cve_id == "CVE-2025-55183" {
        match cdn.as_str() {
            "Cloudflare" => {
                // Cloudflare deployed rules for source code exposure
                // Paid Ruleset: 17c5123f1ac049818765ebf2fefb4e9b
                // Free Ruleset: 3114709a3c3b4e3685052c7b251e86aa
                debug!("Target is behind Cloudflare WAF - CVE-2025-55183 is blocked by default");
                return Some("Cloudflare WAF (rule 17c5123f/3114709a)".to_string());
            }
            "AWS CloudFront" => {
                debug!("Target may be protected by AWS WAF - verify WAF rules are enabled");
                return Some("AWS WAF (verify rules are enabled)".to_string());
            }
            "Akamai" => {
                debug!("Target may be protected by Akamai - verify App & API Protector is enabled");
                return Some("Akamai (verify App & API Protector)".to_string());
            }
            _ => {}
        }
    }

    // WAFs with known CVE-2025-55184 (React RSC DoS via cyclic Promise) protection
    // Reference: https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/
    if cve_id == "CVE-2025-55184" {
        match cdn.as_str() {
            "Cloudflare" => {
                // Cloudflare deployed rules for DoS protection
                // Paid Ruleset: 2694f1610c0b471393b21aef102ec699
                debug!("Target is behind Cloudflare WAF - CVE-2025-55184 is blocked by default");
                return Some("Cloudflare WAF (rule 2694f161)".to_string());
            }
            "AWS CloudFront" => {
                debug!("Target may be protected by AWS WAF - verify WAF rules are enabled");
                return Some("AWS WAF (verify rules are enabled)".to_string());
            }
            "Akamai" => {
                debug!("Target may be protected by Akamai - verify App & API Protector is enabled");
                return Some("Akamai (verify App & API Protector)".to_string());
            }
            _ => {}
        }
    }

    None
}

/// Determines which scanner categories should be skipped for CDN-protected targets
pub fn get_scanners_to_skip_for_cdn(cdn_name: &str) -> Vec<String> {
    debug!(
        "Target is CDN-protected ({}), skipping server-side tests",
        cdn_name
    );

    // Skip server-side vulnerability tests that CDNs would block
    vec![
        "sqli".to_string(),               // SQL Injection (server-side)
        "command_injection".to_string(),  // Command Injection (server-side)
        "path_traversal".to_string(),     // Path Traversal (server-side)
        "nosql".to_string(),              // NoSQL Injection (server-side)
        "ldap_injection".to_string(),     // LDAP Injection (server-side)
        "xxe".to_string(),                // XXE (server-side)
        "template_injection".to_string(), // Template Injection (server-side)
        "code_injection".to_string(),     // Code Injection (server-side)
        "ssi_injection".to_string(),      // SSI Injection (server-side)
        "xml_injection".to_string(),      // XML Injection (server-side)
        "xpath_injection".to_string(),    // XPath Injection (server-side)
    ]
}

/// Determines which scanner categories should still run on CDN-protected targets
pub fn get_scanners_for_cdn() -> Vec<String> {
    // Only test client-side and CDN-specific vulnerabilities
    vec![
        "xss".to_string(),                   // XSS (client-side)
        "cors".to_string(),                  // CORS (CDN config)
        "security_headers".to_string(),      // Security Headers (CDN config)
        "clickjacking".to_string(),          // Clickjacking (client-side)
        "open_redirect".to_string(),         // Open Redirect (routing)
        "crlf_injection".to_string(),        // CRLF Injection (headers)
        "cache_poisoning".to_string(),       // Cache Poisoning (CDN-specific)
        "host_header_injection".to_string(), // Host Header (CDN routing)
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_cloudflare_detection() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "123456".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 0,
        };

        assert_eq!(is_cdn_protected(&response), Some("Cloudflare".to_string()));
    }

    #[test]
    fn test_aws_cloudfront_detection() {
        let mut headers = HashMap::new();
        headers.insert("x-amz-cf-id".to_string(), "abc123".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 0,
        };

        assert_eq!(
            is_cdn_protected(&response),
            Some("AWS CloudFront".to_string())
        );
    }

    #[test]
    fn test_no_cdn() {
        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 0,
        };

        assert_eq!(is_cdn_protected(&response), None);
    }
}
