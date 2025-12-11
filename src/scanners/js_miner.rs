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
        info!("Discovered {} JavaScript files", js_files.len());

        // Analyze inline scripts
        total_tests += self.analyze_inline_scripts(html, url, &mut all_vulnerabilities);

        // Analyze JavaScript files (limit to 20 for performance)
        let files_to_analyze: Vec<String> = js_files.into_iter().take(20).collect();

        for js_url in files_to_analyze {
            let tests = self.analyze_js_file(&js_url, &mut analyzed_urls, &mut all_vulnerabilities).await;
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

        // Extract script tags with src attribute
        let script_regex = Regex::new(r#"<script[^>]+src=["']([^"']+)["']"#).unwrap();
        for cap in script_regex.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let mut js_url = src.as_str().to_string();

                // Handle relative URLs
                if js_url.starts_with("//") {
                    js_url = format!("{}{}", url_obj.scheme(), js_url);
                } else if js_url.starts_with('/') {
                    js_url = format!("{}{}", origin, js_url);
                } else if !js_url.starts_with("http") {
                    js_url = format!("{}/{}", origin, js_url);
                }

                if !js_files.contains(&js_url) {
                    js_files.push(js_url);
                }
            }
        }

        // Add common Next.js paths
        let nextjs_paths = vec![
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/framework.js",
            "/_next/static/chunks/pages/_app.js",
            "/_next/static/chunks/pages/index.js",
        ];

        for path in nextjs_paths {
            let full_url = format!("{}{}", origin, path);
            if !js_files.contains(&full_url) {
                js_files.push(full_url);
            }
        }

        js_files
    }

    /// Analyze inline scripts in HTML
    fn analyze_inline_scripts(&self, html: &str, location: &str, vulnerabilities: &mut Vec<Vulnerability>) -> usize {
        let mut tests_run = 0;

        let inline_script_regex = Regex::new(r#"<script[^>]*>([\s\S]*?)</script>"#).unwrap();

        for (index, cap) in inline_script_regex.captures_iter(html).enumerate() {
            if let Some(script_content) = cap.get(1) {
                let content = script_content.as_str();
                if content.trim().len() > 50 {
                    let inline_location = format!("{}#inline-{}", location, index);
                    tests_run += 1;
                    self.analyze_js_content(content, &inline_location, vulnerabilities);
                }
            }
        }

        tests_run
    }

    /// Analyze a JavaScript file
    async fn analyze_js_file(&self, js_url: &str, analyzed_urls: &mut HashSet<String>, vulnerabilities: &mut Vec<Vulnerability>) -> usize {
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
                    // Limit file size to 5MB
                    if response.body.len() <= 5 * 1024 * 1024 {
                        self.analyze_js_content(&response.body, js_url, vulnerabilities);
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

    /// Analyze JavaScript content for sensitive data
    fn analyze_js_content(&self, content: &str, location: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        // AWS Keys
        if let Some(findings) = self.scan_pattern(content, r"AKIA[0-9A-Z]{16}", "AWS Access Key") {
            for evidence in findings.into_iter().take(3) {
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
            vulnerabilities.push(self.create_vulnerability(
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
            vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
                    "Environment Variable Reference",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "Ensure environment variables don't contain sensitive data accessible client-side.",
                ));
            }
        }

        // GraphQL Queries/Mutations/Fragments (flexible for minified code)
        if let Some(findings) = self.scan_pattern(content, r"(?i)(query|mutation|fragment)\s*[A-Za-z_][A-Za-z0-9_]*", "GraphQL Operation") {
            for evidence in findings.into_iter().take(5) {
                vulnerabilities.push(self.create_vulnerability(
                    "GraphQL Operation Discovered",
                    location,
                    &evidence,
                    Severity::Info,
                    "CWE-200",
                    "GraphQL operations expose API schema. Ensure proper authorization on all queries/mutations.",
                ));
            }
        }

        // GraphQL Endpoint URLs (handles various formats)
        if let Some(findings) = self.scan_pattern(content, r"https?://[a-zA-Z0-9.\-]+[:/][^\s\"'<>]*graphql", "GraphQL Endpoint") {
            for evidence in findings.into_iter().take(3) {
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
        if let Some(findings) = self.scan_pattern(content, r"https://[a-zA-Z0-9.\-]+\.[a-z]{2,}/[^\s\"'<>]*", "External URL") {
            // Filter to only API-like URLs
            let api_findings: Vec<String> = findings.into_iter()
                .filter(|url| {
                    url.contains("/api") ||
                    url.contains("/v1") || url.contains("/v2") || url.contains("/v3") ||
                    url.contains("graphql") ||
                    url.starts_with("https://api.")
                })
                .take(5)
                .collect();

            for evidence in api_findings {
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
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
                vulnerabilities.push(self.create_vulnerability(
                    "Internal Network URL Exposed",
                    location,
                    &evidence,
                    Severity::Medium,
                    "CWE-200",
                    "Internal/private network URL found in client-side code. This may leak infrastructure details.",
                ));
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
