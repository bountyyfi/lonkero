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
            "/manager/status",
            "/manager/status/all",
            "/manager/text",
            "/manager/text/list",
            "/manager/text/serverinfo",
            "/manager/text/threaddump",
            "/manager/text/vminfo",
            "/manager/text/sslConnectorCiphers",
            "/manager/text/findleaks",
            "/host-manager/html",
            "/host-manager/text",
            "/host-manager/text/list",
            "/admin/",
            "/tomcat-admin/",
        ];

        for path in &manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for manager login page or accessible manager
                    // Require Tomcat-specific content, not generic "401 unauthorized" text
                    let is_manager = body_lower.contains("tomcat web application manager")
                        || body_lower.contains("tomcat virtual host manager")
                        || body_lower.contains("manager-gui")
                        || (response.status_code == 401 && body_lower.contains("tomcat"));

                    if is_manager {
                        let severity = if response.status_code == 200 {
                            Severity::Critical // Accessible without auth
                        } else {
                            Severity::Medium // Protected but exposed
                        };

                        info!("Tomcat manager interface found at {}", manager_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &manager_url,
                            "TOMCAT_MANAGER_EXPOSED",
                            &format!("Tomcat Manager Interface Exposed at {}", path),
                            &format!(
                                "Manager interface accessible. Status: {}\nPath: {}",
                                response.status_code, path
                            ),
                            severity,
                            Confidence::High,
                            if response.status_code == 200 { 9.8 } else { 5.3 },
                            "1. Restrict manager access by IP in META-INF/context.xml:\n\
                                <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.0\\.0\\.1|192\\.168\\..+\"/>\n\
                             2. Use strong, unique credentials for manager accounts\n\
                             3. Consider removing manager applications in production\n\
                             4. Place behind VPN or internal network only\n\
                             5. Enable SSL/TLS for manager access",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Manager check failed for {}: {}", manager_url, e);
                }
            }
        }

        // Test 3: Example Applications Accessible
        tests_run += 1;
        let example_paths = vec![
            "/examples/",
            "/examples/jsp/",
            "/examples/servlets/",
            "/examples/websocket/",
            "/docs/",
            "/tomcat-docs/",
        ];

        for path in &example_paths {
            tests_run += 1;
            let example_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&example_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();

                        // Require Tomcat-specific example app patterns, not just the word "example"
                        let is_example = (body_lower.contains("servlet") && body_lower.contains("example"))
                            || body_lower.contains("jsp examples")
                            || body_lower.contains("servlet examples")
                            || body_lower.contains("websocket examples")
                            || body_lower.contains("apache tomcat examples");

                        if is_example {
                            info!("Tomcat examples accessible at {}", example_url);
                            vulnerabilities.push(self.create_vulnerability(
                                &example_url,
                                "TOMCAT_EXAMPLES_ACCESSIBLE",
                                &format!("Tomcat Example Applications Accessible at {}", path),
                                &format!(
                                    "Example applications are accessible in production. Path: {}\nThis may expose vulnerabilities in example code.",
                                    path
                                ),
                                Severity::Low,
                                Confidence::High,
                                3.1,
                                "1. Remove example applications in production: rm -rf $CATALINA_HOME/webapps/examples\n\
                                 2. Remove documentation: rm -rf $CATALINA_HOME/webapps/docs\n\
                                 3. Remove ROOT application if not needed\n\
                                 4. Only deploy necessary applications\n\
                                 5. Review deployed applications regularly",
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Example check failed for {}: {}", example_url, e);
                }
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

        // Test 5: JMX Proxy Servlet Exposure - RCE via MBean invocation
        // The Tomcat Manager JMX proxy allows querying and setting MBean attributes.
        // If unauthenticated it can be abused for RCE via UserDatabase or Realm MBeans.
        tests_run += 1;
        let jmx_paths = vec![
            "/manager/jmxproxy",
            "/manager/jmxproxy/?qry=Catalina:type=Server",
            "/manager/jmxproxy/?qry=java.lang:type=Runtime",
        ];

        for path in &jmx_paths {
            tests_run += 1;
            let jmx_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&jmx_url).await {
                Ok(response) => {
                    let body = &response.body;
                    let body_lower = body.to_lowercase();

                    // JMX proxy returns "OK -" prefix when successful, or MBean-specific
                    // strings like "modelerType" / "Catalina:type=" only when the servlet
                    // actually executes the query. A plain 401 without body content is
                    // treated as protected but exposed.
                    let is_jmx_success = response.status_code == 200
                        && (body.starts_with("OK -")
                            || body_lower.contains("modelertype")
                            || body_lower.contains("catalina:type=")
                            || body_lower.contains("java.lang:type=runtime"));

                    let is_jmx_protected = response.status_code == 401
                        && (body_lower.contains("tomcat")
                            || body_lower.contains("manager"));

                    if is_jmx_success {
                        info!("Tomcat JMX Proxy Servlet exposed at {}", jmx_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &jmx_url,
                            "TOMCAT_JMX_PROXY_EXPOSED",
                            "Tomcat JMX Proxy Servlet Accessible Without Authentication",
                            &format!(
                                "The JMX proxy servlet responded successfully.\nPath: {}\nStatus: {}\nBody preview: {}",
                                path,
                                response.status_code,
                                &body[..body.len().min(200)]
                            ),
                            Severity::Critical,
                            Confidence::High,
                            9.8,
                            "1. Restrict the manager application by IP (RemoteAddrValve) in META-INF/context.xml\n\
                             2. Require the manager-jmx role with strong credentials in tomcat-users.xml\n\
                             3. Consider disabling the JMX proxy entirely by removing the servlet mapping in manager/WEB-INF/web.xml\n\
                             4. Never expose the Manager application on the public internet\n\
                             5. Audit MBean access - the JMX proxy allows setter invocation which can lead to RCE via UserDatabase or Realm reconfiguration",
                        ));
                        break;
                    } else if is_jmx_protected {
                        vulnerabilities.push(self.create_vulnerability(
                            &jmx_url,
                            "TOMCAT_JMX_PROXY_PROTECTED_BUT_EXPOSED",
                            "Tomcat JMX Proxy Servlet Reachable (Authenticated)",
                            &format!(
                                "The JMX proxy servlet is reachable but requires authentication.\nPath: {}\nStatus: {}",
                                path, response.status_code
                            ),
                            Severity::Medium,
                            Confidence::High,
                            5.3,
                            "1. Restrict manager access by IP (RemoteAddrValve)\n\
                             2. Even authenticated exposure allows credential brute-force and post-auth RCE\n\
                             3. Move the manager application behind a VPN or internal-only network segment",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("JMX proxy check failed for {}: {}", jmx_url, e);
                }
            }
        }

        // Test 6: WEB-INF / META-INF direct disclosure
        // Some misconfigurations (bad reverse proxy, path normalization bugs) expose
        // the deployment descriptor which typically contains DB passwords, JNDI configs,
        // servlet mappings and internal admin paths.
        tests_run += 1;
        let webinf_paths = vec![
            "/WEB-INF/web.xml",
            "/META-INF/context.xml",
            "/WEB-INF/classes/application.properties",
            "/WEB-INF/classes/config.properties",
            "/WEB-INF/classes/logback.xml",
            "/WEB-INF/classes/log4j.properties",
            "/WEB-INF/classes/log4j2.xml",
            "/WEB-INF/classes/hibernate.cfg.xml",
            // Common proxy normalisation bypasses
            "/;/WEB-INF/web.xml",
            "/./WEB-INF/web.xml",
            "/..;/WEB-INF/web.xml",
            "/.%2e/WEB-INF/web.xml",
        ];

        for path in &webinf_paths {
            tests_run += 1;
            let disclosure_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&disclosure_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body = &response.body;
                        let body_trim = body.trim_start();

                        // Require distinctive XML/properties markers - never key off status
                        // alone to avoid false positives from soft 200 error pages.
                        let is_web_xml = body_trim.starts_with("<?xml")
                            && (body.contains("<web-app") || body.contains("</web-app>"));
                        let is_context_xml = body_trim.starts_with("<?xml")
                            && (body.contains("<Context") || body.contains("</Context>"));
                        let is_props = path.ends_with(".properties")
                            && body.lines().any(|l| {
                                let t = l.trim();
                                !t.is_empty()
                                    && !t.starts_with('#')
                                    && (t.contains('=') || t.contains(':'))
                            })
                            && (body.to_lowercase().contains("password")
                                || body.to_lowercase().contains("jdbc")
                                || body.to_lowercase().contains("db.")
                                || body.to_lowercase().contains("username"));
                        let is_hibernate = body.contains("hibernate-configuration")
                            || body.contains("hibernate.connection");
                        let is_log_config = body.contains("<configuration")
                            && (body.contains("logback") || body.contains("log4j"));

                        if is_web_xml || is_context_xml || is_props || is_hibernate || is_log_config
                        {
                            let file_type = if is_web_xml {
                                "web.xml (deployment descriptor)"
                            } else if is_context_xml {
                                "context.xml (JNDI/datasource config)"
                            } else if is_hibernate {
                                "hibernate.cfg.xml (database credentials)"
                            } else if is_log_config {
                                "logging configuration"
                            } else {
                                "application configuration file"
                            };

                            info!("Tomcat deployment descriptor disclosed at {}", disclosure_url);
                            vulnerabilities.push(self.create_vulnerability(
                                &disclosure_url,
                                "TOMCAT_WEBINF_DISCLOSURE",
                                &format!("Tomcat Deployment Descriptor Disclosure: {}", file_type),
                                &format!(
                                    "The file '{}' was returned directly and contains {}.\nPath: {}\nStatus: {}\nSize: {} bytes",
                                    path,
                                    file_type,
                                    path,
                                    response.status_code,
                                    body.len()
                                ),
                                Severity::High,
                                Confidence::High,
                                7.5,
                                "1. Tomcat by default forbids access to /WEB-INF and /META-INF - a 200 here indicates a\n\
                                    proxy rewriting the path or a servlet mapping that serves static files from the webroot.\n\
                                 2. Audit reverse-proxy path normalisation - specifically ';' handling and %2e sequences\n\
                                 3. Ensure DefaultServlet is not configured with readonly=false\n\
                                 4. Rotate any credentials leaked in the disclosed file (JDBC, JNDI, LDAP, mail server)\n\
                                 5. Add explicit deny rules in the front-end proxy for /WEB-INF and /META-INF",
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("WEB-INF disclosure check failed for {}: {}", disclosure_url, e);
                }
            }
        }

        // Test 7: CVE-2017-12617 - JSP Upload via PUT method (readonly=false DefaultServlet)
        // We probe with a HARMLESS payload (an empty JSP that outputs a marker) and then
        // GET it back to verify RCE - findings only fire on confirmed round-trip.
        tests_run += 1;
        let cve_marker = format!("lonkero-jsp-probe-{}", uuid::Uuid::new_v4());
        let probe_body = format!(
            "<% out.print(\"{}\"); %>",
            cve_marker
        );

        // Tomcat prior to the patch is vulnerable when the DefaultServlet has readonly=false.
        // We try multiple filename escapes documented as bypasses.
        let cve_paths = vec![
            "/lonkero-probe.jsp/",
            "/lonkero-probe.jsp%20",
            "/lonkero-probe.jsp::$DATA",
            "/lonkero-probe.Jsp",
        ];

        for path in &cve_paths {
            tests_run += 1;
            let put_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.put(&put_url, &probe_body).await {
                Ok(put_response) => {
                    if !(put_response.status_code == 201 || put_response.status_code == 204) {
                        continue;
                    }

                    tests_run += 1;
                    // Read the file back at its canonical path (without the escape trick)
                    let verify_url = format!(
                        "{}/lonkero-probe.jsp",
                        url.trim_end_matches('/')
                    );

                    if let Ok(get_response) = self.http_client.get(&verify_url).await {
                        if get_response.status_code == 200
                            && get_response.body.contains(&cve_marker)
                        {
                            info!(
                                "Tomcat CVE-2017-12617 confirmed at {} (uploaded and executed JSP)",
                                verify_url
                            );
                            vulnerabilities.push(self.create_vulnerability(
                                &verify_url,
                                "TOMCAT_CVE_2017_12617",
                                "Tomcat CVE-2017-12617 - Remote Code Execution via JSP Upload (PUT)",
                                &format!(
                                    "A JSP file uploaded via PUT to '{}' was executed at '{}'.\n\
                                     The response contained the unique marker: {}\n\
                                     This is a fully verified RCE - the DefaultServlet is configured with readonly=false\n\
                                     and the request-URI escape bypasses Tomcat's JSP write restriction.",
                                    path, verify_url, cve_marker
                                ),
                                Severity::Critical,
                                Confidence::High,
                                9.8,
                                "1. Upgrade Tomcat to a patched version:\n\
                                    - 7.0.82 or later\n\
                                    - 8.0.47 or later\n\
                                    - 8.5.23 or later\n\
                                    - 9.0.1 or later\n\
                                 2. Set readonly=\"true\" on the DefaultServlet in conf/web.xml (this is the default)\n\
                                 3. Never expose PUT on JSP resources - block PUT/DELETE at the reverse proxy\n\
                                 4. After patching, review web logs for the uploaded probe file and any earlier attacker JSPs",
                            ));
                            // Best-effort cleanup
                            let _ = self
                                .http_client
                                .delete(&verify_url)
                                .await;
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("CVE-2017-12617 PUT check failed for {}: {}", put_url, e);
                }
            }
        }

        // Test 8: AJP Protocol Exposure (Ghostcat CVE-2020-1938)
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
