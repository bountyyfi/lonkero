// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
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

    /// Run JavaScript mining scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting JavaScript mining scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut analyzed_urls: HashSet<String> = HashSet::new();
        let mut seen_evidence: HashSet<String> = HashSet::new(); // Deduplication

        // Parse target URL to get host
        let target_host = match url::Url::parse(url) {
            Ok(u) => u.host_str().unwrap_or("").to_lowercase(),
            Err(_) => return Ok((all_vulnerabilities, 0)),
        };

        // Get initial HTML response
        let initial_response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                info!("Failed to fetch initial page: {}", e);
                return Ok((all_vulnerabilities, 0));
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
        total_tests += self.analyze_inline_scripts(html, url, &mut all_vulnerabilities, &mut seen_evidence);

        // Analyze JavaScript files (limit to 20 for performance)
        let files_to_analyze: Vec<String> = first_party_files.into_iter().take(20).collect();

        for js_url in &files_to_analyze {
            info!("[JS-Miner] Analyzing: {}", js_url);
        }

        for js_url in files_to_analyze {
            let tests = self.analyze_js_file(&js_url, &mut analyzed_urls, &mut all_vulnerabilities, &mut seen_evidence).await;
            total_tests += tests;
        }

        info!(
            "JavaScript mining scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
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
                // Skip common false positives
                if !evidence.contains("placeholder") && !evidence.contains("example") && !evidence.contains("****") {
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
}
