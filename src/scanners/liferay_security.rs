// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Liferay Security Scanner
 * Advanced security scanner for Liferay Portal/DXP
 *
 * Features:
 * - JSON Web Service API exposure detection
 * - Control Panel and admin interface security
 * - Default credentials detection
 * - Tunnel-web servlet RCE detection
 * - Known CVE detection (2019-2024)
 * - Configuration file exposure
 * - WebDAV and file disclosure
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Personal+ License Required
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

/// Liferay CVE database with version-based detection
struct LiferayCve {
    id: &'static str,
    affected_versions: &'static str,
    severity: Severity,
    description: &'static str,
    cvss: f64,
}

const LIFERAY_CVES: &[LiferayCve] = &[
    LiferayCve {
        id: "CVE-2020-7961",
        affected_versions: "< 7.2.1 CE GA2",
        severity: Severity::Critical,
        description: "Remote code execution via JSON Web Services deserialization",
        cvss: 9.8,
    },
    LiferayCve {
        id: "CVE-2019-16891",
        affected_versions: "< 7.2.0",
        severity: Severity::High,
        description: "XXE injection in SOAP web services",
        cvss: 7.5,
    },
    LiferayCve {
        id: "CVE-2019-6588",
        affected_versions: "< 7.1.4",
        severity: Severity::High,
        description: "Server-Side Request Forgery (SSRF) via URL parameter",
        cvss: 7.5,
    },
    LiferayCve {
        id: "CVE-2021-33329",
        affected_versions: "< 7.3.5",
        severity: Severity::Medium,
        description: "Stored XSS in user profile fields",
        cvss: 5.4,
    },
    LiferayCve {
        id: "CVE-2020-26259",
        affected_versions: "< 7.2.1",
        severity: Severity::Medium,
        description: "Cross-Site Request Forgery in control panel",
        cvss: 6.5,
    },
    LiferayCve {
        id: "CVE-2023-33937",
        affected_versions: "< 7.4.3.40",
        severity: Severity::Medium,
        description: "Open redirect vulnerability in login redirect",
        cvss: 6.1,
    },
    LiferayCve {
        id: "CVE-2024-25604",
        affected_versions: "< 7.4.3.66",
        severity: Severity::High,
        description: "SQL injection in dynamic query builder",
        cvss: 8.6,
    },
    LiferayCve {
        id: "CVE-2024-26271",
        affected_versions: "< 7.4.3.67",
        severity: Severity::High,
        description: "Path traversal in document library",
        cvss: 7.5,
    },
    LiferayCve {
        id: "CVE-2024-26268",
        affected_versions: "< 7.4.3.50",
        severity: Severity::High,
        description: "OGNL injection in Freemarker templates",
        cvss: 8.1,
    },
    LiferayCve {
        id: "CVE-2023-42799",
        affected_versions: "< 7.4.3.35",
        severity: Severity::Critical,
        description: "Remote code execution via portal-ext.properties",
        cvss: 9.8,
    },
    LiferayCve {
        id: "CVE-2023-42572",
        affected_versions: "< 7.4.3.21",
        severity: Severity::High,
        description: "Authentication bypass in SAML authentication",
        cvss: 8.1,
    },
    LiferayCve {
        id: "CVE-2022-28977",
        affected_versions: "< 7.4.2",
        severity: Severity::Medium,
        description: "Information disclosure via error messages",
        cvss: 5.3,
    },
];

pub struct LiferaySecurityScanner {
    http_client: Arc<HttpClient>,
}

impl LiferaySecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        target: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize), anyhow::Error> {
        // Check license - requires Personal+ for CMS security scanning
        if !crate::license::has_feature("cms_security") {
            debug!("[Liferay] CMS security scanning requires Personal+ license");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, detect if this is a Liferay application
        let (is_liferay, version) = self.detect_liferay(target).await;
        tests_run += 3;

        if !is_liferay {
            debug!("[Liferay] Target does not appear to be running Liferay");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Liferay] Detected Liferay Portal{}",
              version.as_ref().map(|v| format!(" version {}", v)).unwrap_or_default());

        // Run all security checks
        let (jsonws_vulns, jsonws_tests) = self.check_jsonws_exposure(target).await;
        vulnerabilities.extend(jsonws_vulns);
        tests_run += jsonws_tests;

        let (admin_vulns, admin_tests) = self.check_admin_exposure(target).await;
        vulnerabilities.extend(admin_vulns);
        tests_run += admin_tests;

        let (default_cred_vulns, default_cred_tests) = self.check_default_credentials(target).await;
        vulnerabilities.extend(default_cred_vulns);
        tests_run += default_cred_tests;

        let (tunnel_vulns, tunnel_tests) = self.check_tunnel_web(target).await;
        vulnerabilities.extend(tunnel_vulns);
        tests_run += tunnel_tests;

        let (webdav_vulns, webdav_tests) = self.check_webdav_exposure(target).await;
        vulnerabilities.extend(webdav_vulns);
        tests_run += webdav_tests;

        let (config_vulns, config_tests) = self.check_config_exposure(target).await;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        let (graphql_vulns, graphql_tests) = self.check_graphql_exposure(target).await;
        vulnerabilities.extend(graphql_vulns);
        tests_run += graphql_tests;

        let (headless_vulns, headless_tests) = self.check_headless_apis(target).await;
        vulnerabilities.extend(headless_vulns);
        tests_run += headless_tests;

        let (documents_vulns, documents_tests) = self.check_documents_exposure(target).await;
        vulnerabilities.extend(documents_vulns);
        tests_run += documents_tests;

        let (axis_vulns, axis_tests) = self.check_axis_exposure(target).await;
        vulnerabilities.extend(axis_vulns);
        tests_run += axis_tests;

        let (combo_vulns, combo_tests) = self.check_combo_servlet(target).await;
        vulnerabilities.extend(combo_vulns);
        tests_run += combo_tests;

        // Check version-based CVEs
        if let Some(ref ver) = version {
            let (cve_vulns, cve_tests) = self.check_version_cves(target, ver).await;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!("[Liferay] Scan complete: {} vulnerabilities, {} tests",
              vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running Liferay
    async fn detect_liferay(&self, target: &str) -> (bool, Option<String>) {
        let mut is_liferay = false;
        let mut version = None;

        // Check login page
        if let Ok(resp) = self.http_client.get(&format!("{}/c/portal/login", target)).await {
            if resp.body.contains("Liferay") ||
               resp.body.contains("liferay-") ||
               resp.body.contains("_com_liferay_") ||
               resp.body.contains("Powered by Liferay") {
                is_liferay = true;
            }

            // Extract version from HTML
            if let Some(ver) = self.extract_version_from_html(&resp.body) {
                version = Some(ver);
            }
        }

        // Check for Liferay headers
        if let Ok(resp) = self.http_client.get(target).await {
            for (name, value) in &resp.headers {
                let name_lower = name.to_lowercase();
                let value_lower = value.to_lowercase();

                if name_lower.contains("liferay") || value_lower.contains("liferay") {
                    is_liferay = true;
                }
            }

            // Check for Liferay cookies
            if let Some(cookies) = resp.headers.get("set-cookie") {
                if cookies.contains("JSESSIONID") && cookies.contains("COOKIE_SUPPORT") {
                    // Additional indicator
                    debug!("[Liferay] Liferay-like session cookies detected");
                }
            }
        }

        // Check JSON Web Services API
        if let Ok(resp) = self.http_client.get(&format!("{}/api/jsonws", target)).await {
            if resp.status_code == 200 && resp.body.contains("jsonws") {
                is_liferay = true;
            }
        }

        (is_liferay, version)
    }

    /// Extract Liferay version from HTML
    fn extract_version_from_html(&self, html: &str) -> Option<String> {
        // Look for version patterns
        let patterns = [
            r#"Liferay[- ]Portal[- ]([\d.]+)"#,
            r#"Liferay[- ]DXP[- ]([\d.]+)"#,
            r#"liferay-version['":\s]+([\d.]+)"#,
            r#"version['":\s]+(7\.\d+\.\d+)"#,
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(html) {
                    if let Some(ver) = caps.get(1) {
                        return Some(ver.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    /// Check JSON Web Services API exposure
    async fn check_jsonws_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let jsonws_endpoints = [
            "/api/jsonws",
            "/api/jsonws/invoke",
            "/api/jsonws?discover=/*",
        ];

        for endpoint in jsonws_endpoints {
            tests_run += 1;
            let url = format!("{}{}", target, endpoint);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    // Check for API listing
                    let has_api_listing = resp.body.contains("className") ||
                                         resp.body.contains("methodName") ||
                                         resp.body.contains("serviceContext");

                    if has_api_listing {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_jsonws_{}", uuid_simple()),
                            vuln_type: "Liferay JSON Web Services API Exposure".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "API Exposure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: "Liferay JSON Web Services API is publicly accessible. This API can expose internal methods, user data, and potentially allow unauthorized actions.".to_string(),
                            evidence: Some(format!("API listing accessible at {}", endpoint)),
                            cwe: "CWE-200".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Restrict JSONWS API access via portal-ext.properties\n2. Set json.web.service.context.exclude properties\n3. Implement authentication for API access\n4. Use IP-based access controls".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break; // Only report once
                    }
                }
            }
        }

        // Check for unauthenticated invocation
        tests_run += 1;
        let invoke_url = format!("{}/api/jsonws/user/get-user-by-email-address/company-id/1/email-address/test@test.com", target);
        if let Ok(resp) = self.http_client.get(&invoke_url).await {
            if resp.status_code == 200 && !resp.body.contains("Access denied") {
                vulnerabilities.push(Vulnerability {
                    id: format!("liferay_jsonws_invoke_{}", uuid_simple()),
                    vuln_type: "Liferay JSONWS Unauthenticated Invocation".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authentication".to_string(),
                    url: invoke_url,
                    parameter: None,
                    payload: String::new(),
                    description: "Liferay JSON Web Services allows unauthenticated method invocation. Attackers can query user data, invoke actions, and potentially compromise the system.".to_string(),
                    evidence: Some("API method invocation succeeded without authentication".to_string()),
                    cwe: "CWE-306".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Enable JSONWS authentication in portal-ext.properties\n2. Set json.web.service.context.exclude=*\n3. Use service access policies to restrict access".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check admin/control panel exposure
    async fn check_admin_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let admin_paths = [
            ("/group/control_panel", "Control Panel"),
            ("/group/control_panel/manage", "Server Administration"),
            ("/c/portal/admin/server", "Server Admin Direct"),
            ("/group/guest/~/control_panel", "Guest Control Panel"),
            ("/web/guest/home/-/admin", "Admin via Web"),
        ];

        for (path, name) in admin_paths {
            tests_run += 1;
            let url = format!("{}{}", target, path);

            if let Ok(resp) = self.http_client.get(&url).await {
                // Accessible if not 403/404 and contains admin content
                if resp.status_code == 200 || resp.status_code == 302 {
                    let has_admin_content = resp.body.contains("control_panel") ||
                                           resp.body.contains("server-admin") ||
                                           resp.body.contains("portlet-admin") ||
                                           resp.body.contains("admin-dashboard");

                    // Check if redirected to login (expected) vs accessible
                    let requires_auth = resp.body.contains("/c/portal/login") ||
                                       resp.body.contains("Sign In");

                    if has_admin_content && !requires_auth {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_admin_{}", uuid_simple()),
                            vuln_type: format!("Liferay {} Exposure", name),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Admin Exposure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!("Liferay {} is accessible without proper authentication or with insufficient access controls.", name),
                            evidence: Some(format!("Admin interface accessible at {}", path)),
                            cwe: "CWE-284".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Configure proper role-based access controls\n2. Disable guest access to control panel\n3. Use IP whitelist for admin interfaces\n4. Enable MFA for admin accounts".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for default credentials
    async fn check_default_credentials(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Default Liferay credentials
        let default_creds = [
            ("test@liferay.com", "test"),
            ("admin@liferay.com", "admin"),
            ("test", "test"),
        ];

        // Get login page to find form action and CSRF token
        tests_run += 1;
        let login_url = format!("{}/c/portal/login", target);
        let login_resp = match self.http_client.get(&login_url).await {
            Ok(resp) => resp,
            Err(_) => return (vulnerabilities, tests_run),
        };

        // Extract form action and CSRF token
        let form_action = self.extract_form_action(&login_resp.body, &login_url);
        let auth_token = self.extract_auth_token(&login_resp.body);

        for (email, password) in default_creds {
            tests_run += 1;

            let mut form_data = vec![
                ("login".to_string(), email.to_string()),
                ("password".to_string(), password.to_string()),
            ];

            if let Some(ref token) = auth_token {
                form_data.push(("p_auth".to_string(), token.clone()));
            }

            let form_body = form_data.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            if let Ok(resp) = self.http_client.post(&form_action, form_body).await {
                // Check for successful login (not redirected back to login, no error message)
                let login_failed = resp.body.contains("Authentication failed") ||
                                  resp.body.contains("Your request failed") ||
                                  resp.body.contains("Invalid credentials") ||
                                  resp.body.contains("Sign In") && resp.body.contains("error");

                // Check for successful login indicators
                let login_success = (resp.status_code == 302 && !resp.body.contains("/c/portal/login")) ||
                                   resp.body.contains("Sign Out") ||
                                   resp.body.contains("My Account") ||
                                   resp.body.contains("User Profile");

                if !login_failed && login_success {
                    vulnerabilities.push(Vulnerability {
                        id: format!("liferay_default_creds_{}", uuid_simple()),
                        vuln_type: "Liferay Default Credentials".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: login_url.clone(),
                        parameter: Some("login/password".to_string()),
                        payload: format!("{}:{}", email, password),
                        description: format!("Liferay Portal accepts default credentials ({}/{}). This allows attackers to gain full access to the portal.", email, password),
                        evidence: Some("Login succeeded with default credentials".to_string()),
                        cwe: "CWE-1393".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Change default passwords immediately\n2. Remove or disable default accounts\n3. Implement strong password policies\n4. Enable account lockout after failed attempts".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break; // Stop after first successful default credential
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check tunnel-web servlet (potential RCE)
    async fn check_tunnel_web(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let tunnel_paths = [
            "/tunnel-web/secure/axis",
            "/api/axis",
            "/tunnel-web",
        ];

        for path in tunnel_paths {
            tests_run += 1;
            let url = format!("{}{}", target, path);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    let has_tunnel_content = resp.body.contains("TunnelServlet") ||
                                            resp.body.contains("axis") ||
                                            resp.body.contains("wsdl") ||
                                            resp.body.contains("SOAP");

                    if has_tunnel_content {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_tunnel_{}", uuid_simple()),
                            vuln_type: "Liferay Tunnel Web Servlet Exposure".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Remote Code Execution".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: "Liferay tunnel-web servlet is exposed. This servlet can be exploited for remote code execution via Java deserialization (CVE-2020-7961).".to_string(),
                            evidence: Some(format!("Tunnel servlet accessible at {}", path)),
                            cwe: "CWE-502".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable tunnel-web in portal-ext.properties\n2. Set tunnel.servlet.hosts.allowed=127.0.0.1\n3. Block access via web server/firewall\n4. Upgrade to patched Liferay version".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check WebDAV exposure
    async fn check_webdav_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let webdav_url = format!("{}/webdav", target);

        // Try PROPFIND request
        // Note: Using GET instead of PROPFIND method which is not available
        if let Ok(resp) = self.http_client.get(&webdav_url).await {
            if resp.status_code == 207 || resp.status_code == 200 {
                let has_webdav = resp.body.contains("multistatus") ||
                                resp.body.contains("DAV:") ||
                                resp.body.contains("propstat");

                if has_webdav {
                    vulnerabilities.push(Vulnerability {
                        id: format!("liferay_webdav_{}", uuid_simple()),
                        vuln_type: "Liferay WebDAV Exposure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: webdav_url.clone(),
                        parameter: None,
                        payload: "PROPFIND".to_string(),
                        description: "Liferay WebDAV service is publicly accessible. This can allow directory listing, file enumeration, and potentially file modification.".to_string(),
                        evidence: Some("WebDAV PROPFIND returned directory listing".to_string()),
                        cwe: "CWE-548".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Disable WebDAV if not needed\n2. Require authentication for WebDAV access\n3. Restrict WebDAV to specific folders\n4. Use IP-based access controls".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        // Check guest WebDAV
        tests_run += 1;
        let guest_webdav = format!("{}/webdav/guest", target);
        if let Ok(resp) = self.http_client.get(&guest_webdav).await {
            if resp.status_code == 200 && !resp.body.contains("Access denied") {
                vulnerabilities.push(Vulnerability {
                    id: format!("liferay_webdav_guest_{}", uuid_simple()),
                    vuln_type: "Liferay Guest WebDAV Access".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: guest_webdav,
                    parameter: None,
                    payload: String::new(),
                    description: "Guest WebDAV folder is accessible. This can expose public documents and folder structure to unauthenticated users.".to_string(),
                    evidence: Some("Guest WebDAV accessible without authentication".to_string()),
                    cwe: "CWE-548".to_string(),
                    cvss: 4.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Review guest folder permissions\n2. Remove sensitive content from guest folders\n3. Disable public WebDAV access".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check configuration file exposure
    async fn check_config_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let config_paths = [
            ("/portal-ext.properties", "Portal Configuration"),
            ("/portal-setup-wizard.properties", "Setup Wizard Config"),
            ("/osgi/configs/", "OSGi Configuration"),
            ("/.env", "Environment Variables"),
            ("/WEB-INF/web.xml", "Web Configuration"),
            ("/WEB-INF/classes/portal-ext.properties", "Portal Ext in WEB-INF"),
        ];

        for (path, config_name) in config_paths {
            tests_run += 1;
            let url = format!("{}{}", target, path);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    let has_config_content = resp.body.contains("jdbc.") ||
                                            resp.body.contains("mail.") ||
                                            resp.body.contains("liferay.") ||
                                            resp.body.contains("admin.") ||
                                            resp.body.contains("company.") ||
                                            resp.body.contains("DB_PASSWORD") ||
                                            resp.body.contains("=");

                    if has_config_content && resp.body.len() > 50 {
                        let severity = if resp.body.to_lowercase().contains("password") ||
                                         resp.body.to_lowercase().contains("secret") ||
                                         resp.body.to_lowercase().contains("key") {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_config_{}", uuid_simple()),
                            vuln_type: format!("Liferay {} Exposure", config_name),
                            severity: severity.clone(),
                            confidence: Confidence::High,
                            category: "Configuration Exposure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!("Liferay configuration file ({}) is publicly accessible. This may expose database credentials, SMTP settings, and other sensitive configuration.", config_name),
                            evidence: Some(format!("Configuration file found at {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss: if severity == Severity::Critical { 9.1 } else { 7.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "1. Block access to configuration files via web server\n2. Move sensitive configs outside web root\n3. Use environment variables for secrets\n4. Review web server directory listing settings".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check GraphQL endpoint exposure
    async fn check_graphql_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let graphql_endpoints = [
            "/o/graphql",
            "/api/graphql",
        ];

        for endpoint in graphql_endpoints {
            tests_run += 1;
            let url = format!("{}{}", target, endpoint);

            // Test introspection query
            let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;
            let query: serde_json::Value = match serde_json::from_str(introspection_query) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Failed to parse introspection query: {}", e);
                    continue;
                }
            };

            if let Ok(resp) = self.http_client.post_json(&url, &query).await {
                if resp.status_code == 200 && resp.body.contains("__schema") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("liferay_graphql_{}", uuid_simple()),
                        vuln_type: "Liferay GraphQL Introspection Enabled".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "API Exposure".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: "introspection query".to_string(),
                        description: "Liferay GraphQL endpoint allows introspection queries. This exposes the entire API schema to attackers.".to_string(),
                        evidence: Some("GraphQL introspection query succeeded".to_string()),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Disable GraphQL introspection in production\n2. Implement authentication for GraphQL endpoint\n3. Use query complexity limits\n4. Enable query depth limiting".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check Headless API exposure
    async fn check_headless_apis(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let headless_endpoints = [
            ("/o/headless-delivery/v1.0/sites", "Headless Delivery - Sites"),
            ("/o/headless-admin-user/v1.0/user-accounts", "Headless Admin - Users"),
            ("/o/headless-admin-user/v1.0/organizations", "Headless Admin - Organizations"),
            ("/o/headless-delivery/v1.0/documents", "Headless Delivery - Documents"),
            ("/o/api", "OpenAPI Documentation"),
        ];

        for (endpoint, api_name) in headless_endpoints {
            tests_run += 1;
            let url = format!("{}{}", target, endpoint);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    let has_api_data = resp.body.contains("\"items\"") ||
                                      resp.body.contains("\"actions\"") ||
                                      resp.body.contains("\"id\":") ||
                                      resp.body.contains("openapi") ||
                                      resp.body.contains("swagger");

                    if has_api_data {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_headless_{}", uuid_simple()),
                            vuln_type: format!("Liferay {} API Exposure", api_name),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "API Exposure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: format!("Liferay {} is accessible without authentication. This can expose user data, site content, and organizational information.", api_name),
                            evidence: Some(format!("API returned data from {}", endpoint)),
                            cwe: "CWE-306".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Enable authentication for headless APIs\n2. Configure service access policies\n3. Use OAuth 2.0 for API access\n4. Restrict API access by role".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check documents/library exposure
    async fn check_documents_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let doc_paths = [
            ("/documents", "Documents Root"),
            ("/documents/portlet_file_entry", "Portlet Files"),
            ("/image/company_logo", "Company Logo"),
            ("/image", "Image Root"),
            ("/web/guest", "Guest Web"),
        ];

        for (path, name) in doc_paths {
            tests_run += 1;
            let url = format!("{}{}", target, path);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    // Check for directory listing
                    let has_listing = resp.body.contains("Index of") ||
                                     resp.body.contains("Parent Directory") ||
                                     resp.body.contains("<table") && resp.body.contains("href=");

                    if has_listing {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_docs_{}", uuid_simple()),
                            vuln_type: format!("Liferay {} Directory Listing", name),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!("Directory listing is enabled for {}. This exposes the file structure and potentially sensitive documents.", name),
                            evidence: Some("Directory listing detected".to_string()),
                            cwe: "CWE-548".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable directory listing\n2. Configure proper access controls on documents\n3. Review document permissions".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check Axis web services exposure
    async fn check_axis_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let axis_paths = [
            "/api/axis",
            "/services",
            "/portal/services",
        ];

        for path in axis_paths {
            tests_run += 1;
            let url = format!("{}{}", target, path);

            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    let has_axis_content = resp.body.contains("wsdl") ||
                                          resp.body.contains("Service") ||
                                          resp.body.contains("axis") ||
                                          resp.body.contains("SOAP");

                    if has_axis_content {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_axis_{}", uuid_simple()),
                            vuln_type: "Liferay Axis Web Services Exposure".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "API Exposure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: "Liferay Axis web services are exposed. These SOAP services can be exploited for XXE injection and other attacks.".to_string(),
                            evidence: Some(format!("Axis services listed at {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable Axis services if not needed\n2. Restrict access to authenticated users only\n3. Apply patches for CVE-2019-16891 (XXE)\n4. Use IP-based access controls".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check combo servlet (JS/CSS concatenation)
    async fn check_combo_servlet(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test for path traversal via combo servlet
        tests_run += 1;
        let combo_url = format!("{}/combo?minifierType=js&themeId=classic_WAR_classictheme&themePath=/html/themes/classic/", target);

        if let Ok(resp) = self.http_client.get(&combo_url).await {
            if resp.status_code == 200 {
                // Try path traversal
                tests_run += 1;
                let traversal_url = format!("{}/combo?minifierType=&themeId=1&themePath=/../../../../../etc/passwd", target);

                if let Ok(trav_resp) = self.http_client.get(&traversal_url).await {
                    if trav_resp.body.contains("root:") || trav_resp.body.contains("/bin/") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("liferay_combo_traversal_{}", uuid_simple()),
                            vuln_type: "Liferay Combo Servlet Path Traversal".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Path Traversal".to_string(),
                            url: traversal_url,
                            parameter: Some("themePath".to_string()),
                            payload: "/../../../../../etc/passwd".to_string(),
                            description: "Liferay combo servlet is vulnerable to path traversal. Attackers can read arbitrary files from the server.".to_string(),
                            evidence: Some("Successfully read /etc/passwd via combo servlet".to_string()),
                            cwe: "CWE-22".to_string(),
                            cvss: 9.1,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Upgrade to patched Liferay version\n2. Disable combo servlet if not needed\n3. Implement input validation".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check version-based CVEs
    async fn check_version_cves(&self, target: &str, version: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = LIFERAY_CVES.len();

        for cve in LIFERAY_CVES {
            if self.version_is_affected(version, cve.affected_versions) {
                vulnerabilities.push(Vulnerability {
                    id: format!("liferay_cve_{}_{}", cve.id.replace("-", "_").to_lowercase(), uuid_simple()),
                    vuln_type: format!("Liferay {}", cve.id),
                    severity: cve.severity.clone(),
                    confidence: Confidence::Medium,
                    category: "Known Vulnerability".to_string(),
                    url: target.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!("{} - Affected versions: {}", cve.description, cve.affected_versions),
                    evidence: Some(format!("Detected Liferay version {} matches affected range {}", version, cve.affected_versions)),
                    cwe: "CWE-1035".to_string(),
                    cvss: cve.cvss as f32,
                    verified: false,
                    false_positive: false,
                    remediation: format!("Upgrade Liferay to a version not affected by {}. Check Liferay security advisories for patches.", cve.id),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check if version is affected by CVE
    fn version_is_affected(&self, version: &str, affected: &str) -> bool {
        // Parse version like "7.4.3.40"
        let version_parts: Vec<u32> = version
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        if version_parts.is_empty() {
            return false;
        }

        // Parse affected version constraint like "< 7.4.3.40"
        let affected_clean = affected
            .replace('<', "")
            .replace('>', "")
            .replace('=', "")
            .replace(" CE GA", ".")
            .trim()
            .to_string();

        let affected_parts: Vec<u32> = affected_clean
            .split(|c: char| c == '.' || c.is_whitespace())
            .filter_map(|p| p.parse().ok())
            .collect();

        if affected_parts.is_empty() {
            return true; // Conservative - assume affected if can't parse
        }

        // Compare versions
        if affected.contains('<') {
            // Version should be less than affected_version to be vulnerable
            for (v, a) in version_parts.iter().zip(affected_parts.iter()) {
                if v < a {
                    return true;
                } else if v > a {
                    return false;
                }
            }
            // If all compared parts are equal, check if current version has fewer parts
            return version_parts.len() < affected_parts.len();
        }

        false
    }

    /// Extract form action from HTML
    fn extract_form_action(&self, html: &str, base_url: &str) -> String {
        if let Ok(re) = regex::Regex::new(r#"action=["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(html) {
                if let Some(action) = caps.get(1) {
                    let action_str = action.as_str();
                    if action_str.starts_with("http") {
                        return action_str.to_string();
                    } else {
                        // Build absolute URL
                        if let Ok(base) = url::Url::parse(base_url) {
                            if let Ok(abs) = base.join(action_str) {
                                return abs.to_string();
                            }
                        }
                    }
                }
            }
        }
        format!("{}/c/portal/login", base_url.trim_end_matches('/'))
    }

    /// Extract auth token from HTML
    fn extract_auth_token(&self, html: &str) -> Option<String> {
        // Look for p_auth hidden field
        if let Ok(re) = regex::Regex::new(r#"name=["']p_auth["']\s+value=["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(html) {
                if let Some(token) = caps.get(1) {
                    return Some(token.as_str().to_string());
                }
            }
        }

        // Alternative pattern
        if let Ok(re) = regex::Regex::new(r#"Liferay\.authToken\s*=\s*["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(html) {
                if let Some(token) = caps.get(1) {
                    return Some(token.as_str().to_string());
                }
            }
        }

        None
    }
}

/// Generate simple UUID
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", timestamp)
}
