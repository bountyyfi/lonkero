// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct VarnishMisconfigScanner {
    http_client: Arc<HttpClient>,
}

impl VarnishMisconfigScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for Varnish cache misconfigurations
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing for Varnish cache misconfigurations");

        // Test 1: Unauthenticated Cache Purge
        // Send PURGE request to check if cache can be purged without authentication
        tests_run += 1;
        let purge_paths = vec![
            "", // Root path
            "/",
            "/index.html",
            "/static/",
            "/assets/",
            "/api/",
        ];

        for path in &purge_paths {
            tests_run += 1;
            let purge_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self
                .http_client
                .request_with_method("PURGE", &purge_url)
                .await
            {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Primary check: successful purge response
                    // body contains '<title>200 Purged</title>' OR '"status": "ok"' AND status == 200
                    let has_purged_title = body_lower.contains("<title>200 purged</title>");
                    let has_status_ok = body_lower.contains("\"status\": \"ok\"")
                        || body_lower.contains("\"status\":\"ok\"")
                        || body_lower.contains("'status': 'ok'");

                    if (has_purged_title || has_status_ok) && response.status_code == 200 {
                        info!(
                            "Unauthenticated Varnish cache purge detected at {}",
                            purge_url
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &purge_url,
                            "VARNISH_UNAUTH_CACHE_PURGE",
                            "Unauthenticated Varnish Cache Purge - Critical Security Issue",
                            &format!(
                                "Cache can be purged without authentication via PURGE method.\n\
                                 URL: {}\nStatus: 200\nEvidence: {}",
                                purge_url,
                                if has_purged_title {
                                    "<title>200 Purged</title>"
                                } else {
                                    "\"status\": \"ok\""
                                }
                            ),
                            Severity::Medium,
                            Confidence::High,
                            6.5,
                            "1. Restrict PURGE method to authorized IPs only in Varnish VCL:\n\
                                acl purge {\n\
                                    \"localhost\";\n\
                                    \"192.168.0.0\"/16;\n\
                                }\n\
                                sub vcl_recv {\n\
                                    if (req.method == \"PURGE\") {\n\
                                        if (!client.ip ~ purge) {\n\
                                            return (synth(405, \"Not allowed.\"));\n\
                                        }\n\
                                        return (purge);\n\
                                    }\n\
                                }\n\
                             2. Implement authentication for cache management\n\
                             3. Use firewall rules to restrict access to cache purge endpoints\n\
                             4. Monitor for unauthorized purge attempts\n\
                             5. Consider using Varnish's built-in ACL for purge authorization",
                        ));
                        break; // Found vulnerability
                    }

                    // Secondary check: Other successful purge indicators
                    let is_successful_purge = response.status_code == 200
                        && (body_lower.contains("purged")
                            || body_lower.contains("cache cleared")
                            || body_lower.contains("invalidated")
                            || body_lower.contains("removed from cache"));

                    if is_successful_purge {
                        info!(
                            "Varnish cache purge successful (secondary indicators) at {}",
                            purge_url
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &purge_url,
                            "VARNISH_UNAUTH_CACHE_PURGE",
                            "Unauthenticated Cache Purge Detected",
                            &format!(
                                "Cache purge operation succeeded without authentication.\nURL: {}\nStatus: {}\nResponse indicates cache was purged.",
                                purge_url, response.status_code
                            ),
                            Severity::Medium,
                            Confidence::Medium,
                            5.5,
                            "1. Implement IP-based or token-based authentication for PURGE requests\n\
                             2. Restrict PURGE method in Varnish VCL configuration\n\
                             3. Use ACLs to limit cache management access\n\
                             4. Log and monitor all cache purge operations",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("PURGE request failed for {}: {}", purge_url, e);
                }
            }
        }

        // Test 2: BAN Method (bulk cache invalidation)
        tests_run += 1;
        match self.http_client.request_with_method("BAN", url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    let is_ban_successful = body_lower.contains("banned")
                        || body_lower.contains("ban added")
                        || body_lower.contains("\"status\": \"ok\"");

                    if is_ban_successful {
                        info!("Unauthenticated Varnish BAN method accessible at {}", url);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "VARNISH_UNAUTH_BAN",
                            "Unauthenticated Varnish BAN Method - Cache Invalidation",
                            &format!(
                                "BAN method accessible without authentication, allowing bulk cache invalidation.\nStatus: {}\nThis can be used for DoS attacks.",
                                response.status_code
                            ),
                            Severity::High,
                            Confidence::High,
                            7.5,
                            "1. Restrict BAN method to internal IPs only\n\
                             2. Implement authentication for BAN operations\n\
                             3. Rate limit cache management operations\n\
                             4. Monitor for cache manipulation attacks",
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("BAN request failed: {}", e);
            }
        }

        // Test 3: Varnish Information Disclosure via Headers
        // IMPORTANT: Only report if we detect VARNISH specifically, not other CDNs like CloudFront
        tests_run += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                let mut disclosed_info = Vec::new();
                let mut is_varnish = false;

                // Check for X-Varnish header (this is Varnish-specific)
                if let Some(x_varnish) = response
                    .headers
                    .get("x-varnish")
                    .or_else(|| response.headers.get("X-Varnish"))
                {
                    disclosed_info.push(format!("X-Varnish: {}", x_varnish));
                    is_varnish = true;
                }

                // Check for Via header (reveals Varnish version)
                if let Some(via) = response
                    .headers
                    .get("via")
                    .or_else(|| response.headers.get("Via"))
                {
                    if via.to_lowercase().contains("varnish") {
                        disclosed_info.push(format!("Via: {}", via));
                        is_varnish = true;
                    }
                }

                // Check for X-Cache header - but ONLY if it mentions Varnish
                // CloudFront, Akamai, etc. also use this header
                if let Some(x_cache) = response
                    .headers
                    .get("x-cache")
                    .or_else(|| response.headers.get("X-Cache"))
                {
                    let x_cache_lower = x_cache.to_lowercase();
                    if x_cache_lower.contains("varnish") {
                        disclosed_info.push(format!("X-Cache: {}", x_cache));
                        is_varnish = true;
                    }
                    // Skip CloudFront, Akamai, Fastly, etc. - they're not Varnish
                    // These CDNs are expected to have cache headers
                }

                // Check for X-Cache-Hits header (Varnish-specific)
                if let Some(hits) = response
                    .headers
                    .get("x-cache-hits")
                    .or_else(|| response.headers.get("X-Cache-Hits"))
                {
                    // X-Cache-Hits is often Varnish-specific
                    disclosed_info.push(format!("X-Cache-Hits: {}", hits));
                    is_varnish = true;
                }

                // Only report if we're confident this is Varnish
                if is_varnish && !disclosed_info.is_empty() {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "VARNISH_INFO_DISCLOSURE",
                        "Varnish Cache Information Disclosure via Headers",
                        &format!(
                            "Varnish-specific headers reveal infrastructure information:\n{}",
                            disclosed_info.join("\n")
                        ),
                        Severity::Info,
                        Confidence::High,
                        2.0,
                        "1. Remove or obscure cache headers in production VCL:\n\
                            sub vcl_deliver {\n\
                                unset resp.http.X-Varnish;\n\
                                unset resp.http.Via;\n\
                                unset resp.http.X-Cache;\n\
                            }\n\
                         2. Configure Varnish to not expose version information\n\
                         3. Consider if cache status headers are necessary for your use case\n\
                         4. Use generic or misleading header values if needed for debugging",
                    ));
                }
            }
            Err(e) => {
                debug!("Header check failed: {}", e);
            }
        }

        // Test 4: Cache Bypass via Headers
        tests_run += 1;
        let bypass_headers = vec![
            ("Cache-Control", "no-cache"),
            ("Pragma", "no-cache"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
        ];

        for (header_name, header_value) in &bypass_headers {
            tests_run += 1;
            let headers = vec![(header_name.to_string(), header_value.to_string())];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    // Check if bypass headers are processed
                    if *header_name == "X-Forwarded-Host" || *header_name == "X-Original-URL" {
                        // These could indicate cache poisoning vectors
                        let body_lower = response.body.to_lowercase();
                        if body_lower.contains("evil.com") || body_lower.contains("/admin") {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "VARNISH_CACHE_POISONING_VECTOR",
                                &format!("Cache Poisoning Vector via {} Header", header_name),
                                &format!(
                                    "The {} header value is reflected in response, indicating potential cache poisoning.\nHeader: {}: {}",
                                    header_name, header_name, header_value
                                ),
                                Severity::High,
                                Confidence::Medium,
                                7.0,
                                "1. Normalize or ignore untrusted headers in VCL:\n\
                                    sub vcl_recv {\n\
                                        unset req.http.X-Forwarded-Host;\n\
                                        unset req.http.X-Original-URL;\n\
                                        unset req.http.X-Rewrite-URL;\n\
                                    }\n\
                                 2. Include relevant headers in cache key (hash)\n\
                                 3. Implement strict header validation\n\
                                 4. Review and test cache key configuration",
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Cache bypass test failed for {}: {}", header_name, e);
                }
            }
        }

        // Test 5: OPTIONS method to discover allowed methods
        tests_run += 1;
        match self.http_client.request_with_method("OPTIONS", url).await {
            Ok(response) => {
                if let Some(allow) = response
                    .headers
                    .get("allow")
                    .or_else(|| response.headers.get("Allow"))
                {
                    let allow_lower = allow.to_lowercase();

                    // Check if dangerous methods are allowed
                    let dangerous_methods = vec!["purge", "ban", "delete", "put", "patch"];
                    let exposed_methods: Vec<&str> = dangerous_methods
                        .iter()
                        .filter(|m| allow_lower.contains(*m))
                        .copied()
                        .collect();

                    if !exposed_methods.is_empty() {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "VARNISH_DANGEROUS_METHODS_ALLOWED",
                            &format!("Dangerous HTTP Methods Allowed: {}", exposed_methods.join(", ").to_uppercase()),
                            &format!(
                                "OPTIONS response reveals dangerous methods are allowed:\nAllow: {}\nDangerous methods: {}",
                                allow, exposed_methods.join(", ").to_uppercase()
                            ),
                            Severity::Medium,
                            Confidence::High,
                            5.0,
                            "1. Restrict dangerous HTTP methods in VCL:\n\
                                sub vcl_recv {\n\
                                    if (req.method != \"GET\" && req.method != \"HEAD\" && \n\
                                        req.method != \"POST\" && req.method != \"OPTIONS\") {\n\
                                        return (synth(405, \"Method Not Allowed\"));\n\
                                    }\n\
                                }\n\
                             2. Remove PURGE/BAN from allowed methods for public access\n\
                             3. Implement proper ACLs for administrative methods\n\
                             4. Review web server configuration as well",
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("OPTIONS request failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        confidence: Confidence,
        cvss: f32,
        remediation: &str,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("varnish_misconfig_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-284".to_string(), // Improper Access Control
            cvss,
            verified,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection_helpers::AppCharacteristics;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> VarnishMisconfigScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        VarnishMisconfigScanner::new(http_client)
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = create_test_scanner();
        // Just verify scanner can be created
        assert!(true);
    }
}
