// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct TomcatMisconfigScanner {
    http_client: Arc<HttpClient>,
}

impl TomcatMisconfigScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for Tomcat misconfigurations
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing for Tomcat misconfigurations");

        // Test 1: Stack Traces Enabled
        // Send malformed query parameter to trigger error page
        tests_run += 1;
        let stack_trace_payloads = vec![
            "?f=\\[",        // Malformed bracket to trigger parse error
            "?f=%5b",        // URL encoded bracket
            "?f={{",         // Template syntax
            "?%00=test",     // Null byte
            "?test[]=",      // Array syntax
            "/?<>=",         // XML-like syntax
            "/..\\..\\",     // Path traversal attempt
            "/%c0%ae%c0%ae", // Overlong UTF-8
        ];

        for payload in &stack_trace_payloads {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for Tomcat stack trace indicators
                    let body_lower = response.body.to_lowercase();

                    let has_tomcat =
                        body_lower.contains("tomcat") || body_lower.contains("apache tomcat");
                    let has_org_apache = body_lower.contains("org.apache.");
                    let has_java_stack = body_lower.contains("java.lang.")
                        || body_lower.contains("javax.")
                        || body_lower.contains("at java.")
                        || body_lower.contains("at org.apache.");
                    let has_exception = body_lower.contains("exception")
                        || body_lower.contains("stacktrace")
                        || body_lower.contains("caused by:");

                    // Primary check: Tomcat + org.apache + 400 status
                    if has_tomcat && has_org_apache && response.status_code == 400 {
                        info!("Tomcat stack traces enabled at {}", test_url);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "TOMCAT_STACKTRACE_ENABLED",
                            "Apache Tomcat Stack Traces Enabled - Information Disclosure",
                            &format!(
                                "Stack trace exposed via malformed request. Payload: {}\nStatus: 400\nEvidence: Contains 'tomcat' and 'org.apache.'",
                                payload
                            ),
                            Severity::Low,
                            Confidence::High,
                            3.7,
                            "1. Disable stack traces in production by configuring error pages in web.xml\n\
                             2. Add custom error pages: <error-page><error-code>400</error-code><location>/error.html</location></error-page>\n\
                             3. Set 'showReport' and 'showServerInfo' to false in server.xml ErrorReportValve\n\
                             4. Review Tomcat's server.xml: <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showReport=\"false\" showServerInfo=\"false\"/>\n\
                             5. Consider using a reverse proxy to filter error responses",
                        ));
                        break; // Found vulnerability, no need to test more payloads
                    }

                    // Secondary check: Java stack trace with exception (broader detection)
                    if (has_java_stack || has_org_apache) && has_exception {
                        info!("Java/Tomcat stack trace detected at {}", test_url);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "JAVA_STACKTRACE_ENABLED",
                            "Java Stack Traces Enabled - Information Disclosure",
                            &format!(
                                "Java stack trace exposed via error response. Payload: {}\nStatus: {}\nEvidence: Contains Java package names and exception details",
                                payload, response.status_code
                            ),
                            Severity::Low,
                            Confidence::High,
                            3.5,
                            "1. Configure custom error pages in web.xml\n\
                             2. Disable detailed error messages in production\n\
                             3. Use try-catch blocks to handle exceptions gracefully\n\
                             4. Log exceptions server-side without exposing to clients\n\
                             5. Review application error handling configuration",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed for {}: {}", test_url, e);
                }
            }
        }

        // Test 2: Tomcat Manager Interface Exposure
        tests_run += 1;
        let manager_paths = vec![
            "/manager/html",
            "/manager/html/",
            "/manager/status",
            "/manager/status/all",
            "/manager/text",
            "/manager/text/list",
            "/manager/jmxproxy",
            "/manager/jmxproxy/?get=Catalina%3Atype%3DServer&att=serverInfo",
            "/host-manager/html",
            "/host-manager/text",
            "/admin/",
            "/admin/login.jsp",
            "/tomcat-admin/",
            // PSI Probe — a third-party Tomcat management webapp routinely deployed
            // under /probe or /psi-probe. Same blast radius as the manager app.
            "/probe/",
            "/probe/sql/datasources.htm",
            "/probe/system/properties.htm",
            "/psi-probe/",
            // Manager app frequently relocated under a path prefix when behind a
            // reverse proxy. These are the patterns we see most in the wild.
            "/tomcat/manager/html",
            "/_tomcat/manager/html",
            "/tomcatmanager/",
        ];

        for path in &manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Require Tomcat-specific content. Generic "401 unauthorized" or
                    // arbitrary 200 SPA shells must never match.
                    let is_manager = body_lower.contains("tomcat web application manager")
                        || body_lower.contains("tomcat virtual host manager")
                        || body_lower.contains("manager-gui")
                        || body_lower.contains("manager-script")
                        || body_lower.contains("manager-jmx")
                        || (response.status_code == 401 && body_lower.contains("tomcat"));

                    // PSI Probe has its own distinctive markers.
                    let is_psi_probe = body_lower.contains("psi probe")
                        || body_lower.contains("psi-probe")
                        || (path.contains("probe")
                            && (body_lower.contains("probe.title")
                                || body_lower.contains("data-source maximum pool size")));

                    // jmxproxy returns plain text like "OK - Attribute get
                    // 'Catalina:type=Server' - serverInfo = Apache Tomcat/9.0.x"
                    let is_jmxproxy = path.contains("jmxproxy")
                        && response.status_code == 200
                        && body_lower.starts_with("ok -")
                        && body_lower.contains("apache tomcat");

                    if is_manager || is_psi_probe || is_jmxproxy {
                        let severity = if response.status_code == 200 {
                            Severity::Critical
                        } else {
                            Severity::Medium
                        };

                        let vtype = if is_psi_probe {
                            "PSI_PROBE_EXPOSED"
                        } else if is_jmxproxy {
                            "TOMCAT_JMXPROXY_EXPOSED"
                        } else {
                            "TOMCAT_MANAGER_EXPOSED"
                        };

                        let title = if is_psi_probe {
                            format!("PSI Probe Management Interface Exposed at {}", path)
                        } else if is_jmxproxy {
                            format!(
                                "Tomcat Manager JMX Proxy Accessible Without Auth at {}",
                                path
                            )
                        } else {
                            format!("Tomcat Manager Interface Exposed at {}", path)
                        };

                        info!("Tomcat management interface found at {}", manager_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &manager_url,
                            vtype,
                            &title,
                            &format!(
                                "Management interface accessible. Status: {}\nPath: {}",
                                response.status_code, path
                            ),
                            severity,
                            Confidence::High,
                            if response.status_code == 200 { 9.8 } else { 5.3 },
                            "1. Restrict manager access by IP in META-INF/context.xml:\n\
                                <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.0\\.0\\.1|192\\.168\\..+\"/>\n\
                             2. Use strong, unique credentials for manager accounts\n\
                             3. Consider removing manager and PSI Probe applications in production\n\
                             4. Place behind VPN or internal network only\n\
                             5. Enable SSL/TLS for manager access\n\
                             6. For the JMX proxy specifically: remove the manager-jmx role from any account reachable from the internet",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Manager check failed for {}: {}", manager_url, e);
                }
            }
        }

        // Test 2b: WEB-INF / META-INF leakage. A correctly configured Tomcat
        // returns 404 for these — anything else (200, directory listing, or the
        // raw web.xml) means a reverse proxy is mapping the path through and
        // exposing servlet config, JDBC URLs and credentials, or class files.
        tests_run += 1;
        let webinf_paths = [
            ("/WEB-INF/web.xml", "web.xml"),
            ("/WEB-INF/", "WEB-INF directory listing"),
            ("/META-INF/context.xml", "context.xml"),
            ("/META-INF/MANIFEST.MF", "MANIFEST.MF"),
            ("/WEB-INF/classes/application.properties", "application.properties under WEB-INF"),
            ("/WEB-INF/classes/application.yml", "application.yml under WEB-INF"),
            ("/WEB-INF/classes/log4j.properties", "log4j.properties under WEB-INF"),
            ("/WEB-INF/classes/hibernate.cfg.xml", "hibernate.cfg.xml under WEB-INF"),
        ];

        for (path, label) in &webinf_paths {
            tests_run += 1;
            let webinf_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&webinf_url).await {
                Ok(response) if response.status_code == 200 => {
                    let body = &response.body;
                    let body_lower = body.to_lowercase();

                    // Hardened content checks — must contain content distinctive to
                    // the file type. Generic 200 responses (SPA shells, etc.) will
                    // not match.
                    let is_web_xml = path.ends_with("web.xml")
                        && body_lower.contains("<web-app")
                        && (body_lower.contains("<servlet")
                            || body_lower.contains("<filter")
                            || body_lower.contains("<servlet-mapping"));

                    let is_context_xml = path.ends_with("context.xml")
                        && (body_lower.contains("<context")
                            && (body_lower.contains("<resource") || body_lower.contains("<valve")));

                    let is_manifest = path.ends_with("MANIFEST.MF")
                        && body.starts_with("Manifest-Version:");

                    let is_properties = path.ends_with(".properties")
                        && (body_lower.contains("jdbc:")
                            || body_lower.contains("spring.")
                            || body_lower.contains("log4j.")
                            || body_lower.contains("hibernate."));

                    let is_yaml = path.ends_with(".yml")
                        && (body_lower.contains("spring:")
                            || body_lower.contains("datasource:")
                            || body_lower.contains("server:"));

                    let is_hibernate = path.ends_with("hibernate.cfg.xml")
                        && body_lower.contains("<hibernate-configuration")
                        && body_lower.contains("<session-factory");

                    let is_dir_listing = path.ends_with("/")
                        && (body_lower.contains("directory listing for /web-inf")
                            || (body_lower.contains("<title>directory listing")
                                && body_lower.contains("web-inf")));

                    let sensitive = is_web_xml
                        || is_context_xml
                        || is_manifest
                        || is_properties
                        || is_yaml
                        || is_hibernate
                        || is_dir_listing;

                    if sensitive {
                        let preview: String = body.chars().take(200).collect();
                        vulnerabilities.push(self.create_vulnerability(
                            &webinf_url,
                            "TOMCAT_WEB_INF_EXPOSED",
                            &format!(
                                "Servlet Deployment Descriptor Exposed: {}",
                                label
                            ),
                            &format!(
                                "WEB-INF/META-INF content reachable via reverse proxy mapping.\n\
                                Path: {}\nStatus: 200\nPreview: {}",
                                path, preview
                            ),
                            Severity::High,
                            Confidence::High,
                            7.5,
                            "1. Tomcat itself never serves WEB-INF or META-INF. If you can reach these paths, a reverse proxy (Apache, nginx, ALB) is rewriting URLs into the webapp's static layer. Fix the proxy rules so paths starting with /WEB-INF/ and /META-INF/ return 404.\n\
                             2. Audit web.xml / context.xml for hardcoded credentials and rotate them — assume they have been exfiltrated.\n\
                             3. Move secrets out of property files baked into the WAR; load them from environment variables or a secret manager.",
                        ));
                    }
                }
                Ok(_) => {}
                Err(e) => debug!("WEB-INF check failed for {}: {}", webinf_url, e),
            }
        }

        // Test 3: Example Applications Accessible
        // The interesting examples aren't the index page — they're individual
        // demo servlets that leak server state or accept attacker-controlled
        // session/cookie input. We probe each one specifically.
        tests_run += 1;
        let example_paths: &[(&str, &[&str], Severity, &str)] = &[
            (
                "/examples/",
                &["jsp examples", "servlet examples", "websocket examples", "apache tomcat examples"],
                Severity::Low,
                "Tomcat examples webapp index",
            ),
            (
                "/examples/jsp/",
                &["jsp examples", "<a href=\"snp/snoop.jsp\""],
                Severity::Low,
                "JSP examples directory",
            ),
            // snoop.jsp dumps the full request: headers, all cookies (including
            // session and SSO cookies of any user who hits the link), remote IP,
            // and server-side environment. Standard XSS-via-trusted-host vector.
            (
                "/examples/jsp/snp/snoop.jsp",
                &["request information", "request method", "remote address", "header values"],
                Severity::Medium,
                "snoop.jsp — full request/header/cookie dump",
            ),
            (
                "/examples/servlets/servlet/SessionExample",
                &["sessions example", "session id", "your session id"],
                Severity::Medium,
                "SessionExample — writes attacker-controlled keys into the JSESSIONID-bound session",
            ),
            (
                "/examples/servlets/servlet/CookieExample",
                &["cookies example", "your cookies"],
                Severity::Medium,
                "CookieExample — sets attacker-controlled cookies on the application's origin",
            ),
            (
                "/examples/servlets/servlet/RequestInfoExample",
                &["request information", "request uri"],
                Severity::Low,
                "RequestInfoExample — request/server info disclosure",
            ),
            (
                "/examples/servlets/servlet/RequestHeaderExample",
                &["request header example", "header name"],
                Severity::Low,
                "RequestHeaderExample — request header dump",
            ),
            (
                "/examples/jsp/cal/cal2.jsp",
                &["calendar", "<form"],
                Severity::Info,
                "JSP calendar example",
            ),
            (
                "/examples/websocket/",
                &["websocket examples", "echo"],
                Severity::Low,
                "WebSocket examples — historically vulnerable echo handler",
            ),
            (
                "/docs/",
                &["apache tomcat", "documentation"],
                Severity::Info,
                "Tomcat documentation app — leaks exact server version",
            ),
            (
                "/tomcat-docs/",
                &["apache tomcat", "documentation"],
                Severity::Info,
                "Tomcat documentation app (alt path)",
            ),
        ];

        for (path, markers, sev, label) in example_paths {
            tests_run += 1;
            let example_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&example_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();

                        // Require at least one example-specific marker so a
                        // generic 200 OK (SPA fallback, vendor portal index)
                        // never matches.
                        let matched = markers.iter().any(|m| body_lower.contains(m));
                        if matched {
                            info!("Tomcat example accessible at {}", example_url);
                            let cvss = match sev {
                                Severity::Medium => 5.3,
                                Severity::Low => 3.1,
                                _ => 0.0,
                            };
                            vulnerabilities.push(self.create_vulnerability(
                                &example_url,
                                "TOMCAT_EXAMPLES_ACCESSIBLE",
                                &format!("Tomcat Example Accessible: {}", label),
                                &format!(
                                    "Example component reachable in production. Path: {}\n\
                                    Why this matters: {}",
                                    path, label
                                ),
                                sev.clone(),
                                Confidence::High,
                                cvss,
                                "1. Remove example applications in production: rm -rf $CATALINA_HOME/webapps/examples\n\
                                 2. Remove documentation: rm -rf $CATALINA_HOME/webapps/docs\n\
                                 3. Remove ROOT application if not needed\n\
                                 4. Only deploy necessary applications\n\
                                 5. Review deployed applications regularly",
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Example check failed for {}: {}", example_url, e);
                }
            }
        }

        // Test 3b: Apache httpd mod_status / mod_info — frequently fronts Tomcat
        // via mod_jk or mod_proxy_ajp. These pages by default require explicit
        // <Location> ACLs; finding them open leaks per-request URLs (including
        // session tokens and one-time auth codes that show up in GET params),
        // worker thread state, and full Apache build configuration.
        tests_run += 1;
        let status_paths = [
            (
                "/server-status",
                Severity::High,
                "Apache mod_status page — per-request worker state with full URLs (including query string tokens) and client IPs",
                &["apache server status", "current time:", "server uptime"][..],
            ),
            (
                "/server-status?full",
                Severity::High,
                "Apache mod_status (full mode) — adds per-thread request data",
                &["apache server status", "current time:", "server uptime"][..],
            ),
            (
                "/server-info",
                Severity::Medium,
                "Apache mod_info page — full compiled configuration, loaded module list and versions",
                &["apache server information", "module name:", "server settings"][..],
            ),
            (
                "/balancer-manager",
                Severity::Critical,
                "Apache mod_proxy_balancer manager — disable, drain, or re-route backend members at will",
                &["balancer manager", "load balancer manager"][..],
            ),
            (
                "/status",
                Severity::Low,
                "Generic /status endpoint — Apache mod_status often mounted here as well",
                &["apache server status"][..],
            ),
            (
                "/jkstatus",
                Severity::High,
                "mod_jk status worker — exposes AJP worker layout and lets requests be routed to internal workers by name",
                &["jk status manager", "jkstatus", "jk status"][..],
            ),
        ];

        for (path, sev, label, markers) in status_paths {
            tests_run += 1;
            let status_url = format!("{}{}", url.trim_end_matches('/'), path);
            match self.http_client.get(&status_url).await {
                Ok(response) if response.status_code == 200 => {
                    let body_lower = response.body.to_lowercase();
                    if markers.iter().any(|m| body_lower.contains(m)) {
                        let cvss = match sev {
                            Severity::Critical => 9.1,
                            Severity::High => 7.5,
                            Severity::Medium => 5.3,
                            _ => 3.1,
                        };
                        info!("Apache status/info page exposed at {}", status_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &status_url,
                            "APACHE_MOD_STATUS_EXPOSED",
                            &format!("Apache Status Module Exposed: {}", label),
                            &format!(
                                "Status/info module reachable without authentication.\n\
                                Path: {}\nLeak: {}",
                                path, label
                            ),
                            sev,
                            Confidence::High,
                            cvss,
                            "1. Bind the module to localhost or an admin VLAN with `Require ip 127.0.0.1 ::1` (or `Order Deny,Allow` on older httpd).\n\
                             2. Remove the `ExtendedStatus On` directive if mod_status is required publicly to suppress per-request URLs.\n\
                             3. For mod_jk: comment out the JkMount for /jkstatus or restrict it via <Location>.\n\
                             4. Treat any URLs visible in past mod_status output as potentially exfiltrated: rotate any session/auth tokens that may have appeared in GET parameters.",
                        ));
                    }
                }
                Ok(_) => {}
                Err(e) => debug!("Status check failed for {}: {}", status_url, e),
            }
        }

        // Test 4: Version Detection via Error Pages
        tests_run += 1;
        let version_paths = vec!["/nonexistent_path_12345", "/WEB-INF/", "/META-INF/"];

        for path in &version_paths {
            tests_run += 1;
            let version_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&version_url).await {
                Ok(response) => {
                    if response.status_code == 404 || response.status_code == 403 {
                        // Check for version disclosure in error page
                        let version_regex = regex::Regex::new(
                            r"(?i)(apache\s+tomcat|tomcat)\s*/?\s*(\d+\.\d+(?:\.\d+)?)",
                        )
                        .ok();

                        if let Some(re) = version_regex {
                            if let Some(caps) = re.captures(&response.body) {
                                if let Some(version) = caps.get(2) {
                                    info!(
                                        "Tomcat version {} disclosed at {}",
                                        version.as_str(),
                                        version_url
                                    );
                                    vulnerabilities.push(self.create_vulnerability(
                                        url,
                                        "TOMCAT_VERSION_DISCLOSURE",
                                        &format!("Apache Tomcat Version Disclosed: {}", version.as_str()),
                                        &format!(
                                            "Server version exposed in error page: Tomcat {}\nPath: {}",
                                            version.as_str(), path
                                        ),
                                        Severity::Info,
                                        Confidence::High,
                                        2.0,
                                        "1. Hide server version in server.xml: <Connector ... server=\"\" />\n\
                                         2. Configure ErrorReportValve with showServerInfo=\"false\"\n\
                                         3. Use custom error pages that don't reveal server info\n\
                                         4. Consider using mod_security or similar WAF\n\
                                         5. Keep Tomcat updated to latest secure version",
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Version check failed for {}: {}", version_url, e);
                }
            }
        }

        // Test 5: AJP Protocol Exposure (Ghostcat CVE-2020-1938)
        tests_run += 1;
        // This is a network-level check, we can only detect via headers or info disclosure
        match self.http_client.get(url).await {
            Ok(response) => {
                // Check for AJP-related headers or info
                let server_header = response
                    .headers
                    .get("server")
                    .or_else(|| response.headers.get("Server"));

                if let Some(server) = server_header {
                    if server.to_lowercase().contains("ajp") {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "TOMCAT_AJP_EXPOSED",
                            "AJP Protocol Potentially Exposed (Ghostcat Risk)",
                            "Server header indicates AJP connector usage. Check if AJP port 8009 is exposed.",
                            Severity::High,
                            Confidence::Low,
                            7.5,
                            "1. Disable AJP if not needed: comment out AJP Connector in server.xml\n\
                             2. If AJP is required, add secretRequired=\"true\" and secret=\"<strong-secret>\"\n\
                             3. Bind AJP to localhost only: address=\"127.0.0.1\"\n\
                             4. Use firewall to block port 8009 from external access\n\
                             5. Update to Tomcat 7.0.100+, 8.5.51+, or 9.0.31+ (patched versions)",
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("AJP check failed: {}", e);
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
            id: format!("tomcat_misconfig_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-200".to_string(), // Information Exposure
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

    fn create_test_scanner() -> TomcatMisconfigScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        TomcatMisconfigScanner::new(http_client)
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = create_test_scanner();
        // Just verify scanner can be created
        assert!(true);
    }
}
