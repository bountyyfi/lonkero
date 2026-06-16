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
        // CRITICAL: First detect if this is actually a caching proxy (Varnish, Nginx, etc.)
        // Don't report cache poisoning on non-caching servers like Cloudflare Workers
        tests_run += 1;

        // Check for caching infrastructure indicators
        let baseline_resp = self.http_client.get(url).await.ok();
        let has_caching_proxy = baseline_resp.as_ref().map(|r| {
            let headers = &r.headers;
            // Check for Varnish-specific headers
            let has_varnish = headers.contains_key("x-varnish")
                || headers.contains_key("X-Varnish")
                || headers.get("via").map(|v| v.to_lowercase().contains("varnish")).unwrap_or(false)
                || headers.get("Via").map(|v| v.to_lowercase().contains("varnish")).unwrap_or(false);

            // Check for generic caching proxy indicators
            let has_cache_headers = headers.contains_key("x-cache")
                || headers.contains_key("X-Cache")
                || headers.contains_key("x-cache-hits")
                || headers.contains_key("X-Cache-Hits")
                || headers.contains_key("cf-cache-status")  // Cloudflare
                || headers.contains_key("x-fastly-request-id");  // Fastly

            // Check for Age header (indicates cached response)
            let has_age = headers.contains_key("age") || headers.contains_key("Age");

            has_varnish || (has_cache_headers && has_age)
        }).unwrap_or(false);

        // Only test cache poisoning if we detect caching infrastructure
        if has_caching_proxy {
            // Each entry: (header_name, header_value, reflection_marker_to_search_for)
            // The marker is a deliberately unique string we inject so a reflection
            // check has zero ambiguity. Markers MUST NOT appear in normal pages,
            // which keeps the false-positive rate at zero.
            const MARKER_DOMAIN: &str = "lonkero-cache-probe.invalid";
            const MARKER_PATH: &str = "/lonkero-cache-probe-marker";
            const MARKER_SCHEME: &str = "lonkeroprobe";
            let bypass_headers: Vec<(&str, String)> = vec![
                ("Cache-Control", "no-cache".to_string()),
                ("Pragma", "no-cache".to_string()),
                // Classic Host-rewrite headers
                ("X-Forwarded-Host", MARKER_DOMAIN.to_string()),
                ("X-Host", MARKER_DOMAIN.to_string()),
                ("X-Forwarded-Server", MARKER_DOMAIN.to_string()),
                ("X-HTTP-Host-Override", MARKER_DOMAIN.to_string()),
                ("Forwarded", format!("host={}", MARKER_DOMAIN)),
                // Scheme-rewrite headers (HSTS bypass / mixed content)
                ("X-Forwarded-Scheme", MARKER_SCHEME.to_string()),
                ("X-Forwarded-Proto", MARKER_SCHEME.to_string()),
                ("X-Forwarded-Ssl", "on".to_string()),
                // URL-rewrite headers (auth bypass / cache key smuggling)
                ("X-Original-URL", MARKER_PATH.to_string()),
                ("X-Rewrite-URL", MARKER_PATH.to_string()),
                ("X-Override-URL", MARKER_PATH.to_string()),
                ("X-HTTP-Method-Override", "GET".to_string()),
                // Prefix-rewrite (path confusion)
                ("X-Forwarded-Prefix", MARKER_PATH.to_string()),
                // Cache-key influencing headers commonly missed in VCL
                ("X-Forwarded-For", "127.0.0.1".to_string()),
                ("X-Real-IP", "127.0.0.1".to_string()),
                ("True-Client-IP", "127.0.0.1".to_string()),
                ("CF-Connecting-IP", "127.0.0.1".to_string()),
            ];

            // Only headers that carry a unique marker can be flagged via
            // reflection - listing them keeps no-marker headers from triggering.
            let host_rewrite_headers = [
                "X-Forwarded-Host",
                "X-Host",
                "X-Forwarded-Server",
                "X-HTTP-Host-Override",
                "Forwarded",
            ];
            let url_rewrite_headers = [
                "X-Original-URL",
                "X-Rewrite-URL",
                "X-Override-URL",
                "X-Forwarded-Prefix",
            ];
            let scheme_rewrite_headers = [
                "X-Forwarded-Scheme",
                "X-Forwarded-Proto",
            ];

            for (header_name, header_value) in &bypass_headers {
                tests_run += 1;
                let headers = vec![(header_name.to_string(), header_value.clone())];

                match self.http_client.get_with_headers(url, headers).await {
                    Ok(response) => {
                        let body = &response.body;
                        // Pick the marker we expect to find reflected. Each
                        // marker is intentionally unique so this is FP-safe.
                        let marker_opt: Option<&str> = if host_rewrite_headers
                            .contains(header_name)
                        {
                            Some(MARKER_DOMAIN)
                        } else if url_rewrite_headers.contains(header_name) {
                            Some(MARKER_PATH)
                        } else if scheme_rewrite_headers.contains(header_name) {
                            Some(MARKER_SCHEME)
                        } else {
                            None
                        };

                        if let Some(marker) = marker_opt {
                            // Reflected in body OR echoed in a Location header
                            // (the most common cache-poisoning primitive in
                            // Varnish/Fastly setups that forward Host into
                            // generated absolute URLs).
                            let location_echoes = response
                                .headers
                                .get("location")
                                .or_else(|| response.headers.get("Location"))
                                .map(|v| v.contains(marker))
                                .unwrap_or(false);
                            let link_echoes = response
                                .headers
                                .get("link")
                                .or_else(|| response.headers.get("Link"))
                                .map(|v| v.contains(marker))
                                .unwrap_or(false);
                            let body_echoes = body.contains(marker);

                            if location_echoes || link_echoes || body_echoes {
                                let where_seen = if location_echoes {
                                    "Location header"
                                } else if link_echoes {
                                    "Link header"
                                } else {
                                    "response body"
                                };
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "VARNISH_CACHE_POISONING_VECTOR",
                                    &format!(
                                        "Cache Poisoning Vector via {} Header",
                                        header_name
                                    ),
                                    &format!(
                                        "The {} header value is reflected in {}, indicating a potential cache poisoning sink.\nHeader sent: {}: {}\nReflection point: {}\nMarker observed: {}",
                                        header_name,
                                        where_seen,
                                        header_name,
                                        header_value,
                                        where_seen,
                                        marker
                                    ),
                                    Severity::High,
                                    Confidence::Medium,
                                    7.0,
                                    "1. Normalize or ignore untrusted headers in VCL:\n\
                                        sub vcl_recv {\n\
                                            unset req.http.X-Forwarded-Host;\n\
                                            unset req.http.X-Host;\n\
                                            unset req.http.X-Forwarded-Server;\n\
                                            unset req.http.X-Forwarded-Scheme;\n\
                                            unset req.http.X-Forwarded-Proto;\n\
                                            unset req.http.X-Forwarded-Prefix;\n\
                                            unset req.http.X-Original-URL;\n\
                                            unset req.http.X-Rewrite-URL;\n\
                                            unset req.http.X-Override-URL;\n\
                                            unset req.http.X-HTTP-Method-Override;\n\
                                            unset req.http.X-HTTP-Host-Override;\n\
                                            unset req.http.Forwarded;\n\
                                        }\n\
                                     2. Add all routing-relevant headers to the cache key (Vary)\n\
                                     3. Validate Host strictly against an allowlist\n\
                                     4. Re-test after changes - the marker should no longer appear",
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Cache bypass test failed for {}: {}", header_name, e);
                    }
                }
            }
        } else {
            debug!("No caching proxy detected, skipping cache poisoning tests");
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
                ml_confidence: None,
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::RngExt;

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
