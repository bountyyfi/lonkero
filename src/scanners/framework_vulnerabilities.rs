// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

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
                &html[start.saturating_sub(200)..start.saturating_add(200).min(html.len())];
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
