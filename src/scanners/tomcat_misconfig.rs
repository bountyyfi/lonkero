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
        //
        // Manager apps are the canonical RCE vector on Tomcat: an attacker with
        // `manager-script` or `manager-gui` access can deploy a WAR and get code
        // execution. Include every path that historically ships with Tomcat or
        // is created by Linux distro packages / OEM images.
        //
        // Detection below still requires a Tomcat-specific string in the body,
        // so path expansion cannot cause FPs on unrelated pages.
        tests_run += 1;
        let manager_paths = vec![
            // Manager (webapp deploy/undeploy, text + HTML + JMX proxy)
            "/manager",
            "/manager/",
            "/manager/html",
            "/manager/html/",
            "/manager/status",
            "/manager/status/all",
            "/manager/text",
            "/manager/text/list",
            "/manager/text/serverinfo",
            "/manager/text/threaddump",
            "/manager/text/vminfo",
            "/manager/text/sslConnectorCiphers",
            "/manager/jmxproxy",
            "/manager/jmxproxy/",
            "/manager/jmxproxy/?qry=java.lang:type=Runtime",
            // Host manager (vhost control, equally dangerous)
            "/host-manager",
            "/host-manager/",
            "/host-manager/html",
            "/host-manager/text",
            "/host-manager/text/list",
            // Historic / distro / OEM variants
            "/admin",
            "/admin/",
            "/admin/html",
            "/tomcat-admin",
            "/tomcat-admin/",
            "/tomcat/manager/html",
            "/tomcatmanager",
            "/_manager/html",
            "/webmanager",
            // Common reverse-proxy rewrites that still front the real manager
            "/app/manager/html",
            "/apps/manager/html",
            "/console/manager/html",
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
        //
        // The default `examples` webapp ships with known-vulnerable demo servlets
        // (SessionExample lets anyone set session attributes; CookieExample
        // lets anyone set cookies on the Tomcat origin — both have been used to
        // chain session fixation and CSRF into privileged areas of the real
        // application). Documentation apps also commonly leak version info.
        tests_run += 1;
        let example_paths = vec![
            "/examples/",
            "/examples/jsp/",
            "/examples/jsp/snp/snoop.jsp",
            "/examples/jsp/num/numguess.jsp",
            "/examples/jsp/sessions/carts.html",
            "/examples/servlets/",
            "/examples/servlets/servlet/SessionExample",
            "/examples/servlets/servlet/CookieExample",
            "/examples/servlets/servlet/RequestInfoExample",
            "/examples/servlets/servlet/RequestHeaderExample",
            "/examples/servlets/servlet/RequestParamExample",
            "/examples/websocket/",
            "/examples/websocket/chat.xhtml",
            "/docs/",
            "/docs/RELEASE-NOTES.txt",
            "/docs/changelog.html",
            "/tomcat-docs/",
            "/sample/",
            "/sample/hello.jsp",
            "/webdav/",
            "/probe/",
            "/balancer/",
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
        let version_paths = vec![
            "/nonexistent_path_12345",
            "/WEB-INF/",
            "/META-INF/",
            "/RELEASE-NOTES.txt",
            "/docs/RELEASE-NOTES.txt",
            "/docs/changelog.html",
        ];

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

        // Test 6: Sensitive Tomcat files / endpoints.
        //
        // These paths are known-sensitive and only trip when the response is
        // clearly the real file (content-anchored match), so we cannot flag
        // unrelated pages. Impact notes inline.
        let sensitive_endpoints: &[(&str, &str, &[&str], Severity, f32, &str)] = &[
            // WEB-INF/web.xml — servlet map, filters, security constraints, DB
            // resource refs, often DataSource credentials in <resource-ref>.
            (
                "/WEB-INF/web.xml",
                "TOMCAT_WEBXML_EXPOSED",
                &["<web-app", "<servlet-mapping", "<servlet>"],
                Severity::High,
                7.5,
                "Deny all access to /WEB-INF/ at the connector or reverse proxy; \
                 this directory must never be served.",
            ),
            // META-INF/context.xml — datasource credentials, valves.
            (
                "/META-INF/context.xml",
                "TOMCAT_CONTEXTXML_EXPOSED",
                &["<Context", "<Resource", "javax.sql.DataSource"],
                Severity::Critical,
                9.1,
                "Block /META-INF/ at the connector; remove any inline passwords \
                 and use secure credential stores instead.",
            ),
            // Tomcat users (manager app credentials — full RCE on exposure).
            (
                "/tomcat-users.xml",
                "TOMCAT_USERS_XML_EXPOSED",
                &["<tomcat-users", "<user ", "roles="],
                Severity::Critical,
                9.8,
                "tomcat-users.xml contains manager credentials. Remove from web \
                 root, block at proxy, and rotate any passwords that were present.",
            ),
            (
                "/conf/tomcat-users.xml",
                "TOMCAT_USERS_XML_EXPOSED",
                &["<tomcat-users", "<user ", "roles="],
                Severity::Critical,
                9.8,
                "Block /conf/ at the connector and rotate any credentials present.",
            ),
            // server.xml — full Tomcat config, Realm credentials, Keystore paths.
            (
                "/conf/server.xml",
                "TOMCAT_SERVERXML_EXPOSED",
                &["<Server ", "<Service ", "<Connector "],
                Severity::Critical,
                9.1,
                "server.xml reveals the full Tomcat topology and often contains \
                 keystore passwords. Block /conf/ at the connector.",
            ),
            (
                "/conf/context.xml",
                "TOMCAT_CONTEXTXML_EXPOSED",
                &["<Context", "<Resource"],
                Severity::High,
                7.5,
                "Block /conf/context.xml at the connector.",
            ),
            (
                "/conf/web.xml",
                "TOMCAT_WEBXML_EXPOSED",
                &["<web-app", "<servlet"],
                Severity::High,
                7.5,
                "Block /conf/web.xml at the connector.",
            ),
            (
                "/conf/catalina.properties",
                "TOMCAT_CATALINA_PROPERTIES_EXPOSED",
                &["catalina.", "common.loader", "tomcat.util.scan"],
                Severity::High,
                7.5,
                "Block /conf/ at the connector; catalina.properties can leak class \
                 loader configuration used to target exploitation.",
            ),
            (
                "/conf/catalina.policy",
                "TOMCAT_CATALINA_POLICY_EXPOSED",
                &["grant codeBase", "permission java.", "catalina"],
                Severity::Medium,
                5.3,
                "Block /conf/ at the connector.",
            ),
            (
                "/conf/logging.properties",
                "TOMCAT_LOGGING_PROPERTIES_EXPOSED",
                &["handlers =", "juli.AsyncFileHandler", ".level"],
                Severity::Low,
                3.7,
                "Block /conf/ at the connector.",
            ),
            // Server status / manager sub-pages that occasionally slip through.
            (
                "/status",
                "TOMCAT_STATUS_EXPOSED",
                &["Server Status", "JVM", "Tomcat"],
                Severity::Medium,
                5.3,
                "Restrict /status and /server-status via RemoteAddrValve or proxy \
                 rules; exposes JVM memory, threads, and request counters.",
            ),
            (
                "/server-status",
                "TOMCAT_SERVER_STATUS_EXPOSED",
                &["Server Status", "JVM", "Tomcat"],
                Severity::Medium,
                5.3,
                "Restrict via RemoteAddrValve or reverse-proxy ACL.",
            ),
            // Classic CVE-2017-12617: PUT-enabled default servlet → JSP upload RCE.
            // Detect the enabler: OPTIONS response advertising PUT on /.
            // (We only flag if Allow header explicitly includes PUT — very low FP.)
            // No request body needed, just OPTIONS via GET isn't possible so we
            // rely on any prior response's `Allow` header if present.
        ];

        for (path, vuln_id, markers, severity, cvss, fix) in sensitive_endpoints {
            tests_run += 1;
            let sensitive_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&sensitive_url).await {
                Ok(response) => {
                    if response.status_code != 200 || response.body.len() < 20 {
                        continue;
                    }
                    // Require *all* structural markers to prevent any chance of
                    // matching a 200-OK SPA shell or generic error page.
                    let body = &response.body;
                    let all_match = markers.iter().all(|m| body.contains(m));
                    if !all_match {
                        continue;
                    }

                    info!("Tomcat sensitive file exposed: {}", sensitive_url);
                    vulnerabilities.push(self.create_vulnerability(
                        &sensitive_url,
                        vuln_id,
                        &format!("Tomcat Sensitive File Exposed: {}", path),
                        &format!(
                            "File {} returned 200 OK ({} bytes) and contains all of: [{}]",
                            path,
                            body.len(),
                            markers.join(", ")
                        ),
                        severity.clone(),
                        Confidence::High,
                        *cvss,
                        fix,
                    ));
                }
                Err(e) => {
                    debug!("Sensitive path check failed for {}: {}", sensitive_url, e);
                }
            }
        }

        // Test 7: CVE-2017-12617 / default-servlet PUT enabled.
        //
        // The default servlet must never accept PUT in production. An OPTIONS
        // probe that answers with `Allow: ... PUT ...` is a direct indicator.
        // This is a zero-FP signal: a reverse proxy normally strips PUT from
        // Allow. If it's there, it's there.
        tests_run += 1;
        if let Ok(response) = self.http_client.request_with_method("OPTIONS", url).await {
            let allow = response
                .headers
                .get("allow")
                .or_else(|| response.headers.get("Allow"))
                .cloned()
                .unwrap_or_default();
            let allow_upper = allow.to_uppercase();
            if allow_upper.contains("PUT") && allow_upper.contains("DELETE") {
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "TOMCAT_PUT_DELETE_ENABLED",
                    "Tomcat Default Servlet Allows PUT/DELETE",
                    &format!(
                        "Server advertised write methods in Allow header.\nAllow: {}",
                        allow
                    ),
                    Severity::High,
                    Confidence::High,
                    7.5,
                    "1. In conf/web.xml set the default servlet `readonly` init-param to `true`\n\
                     2. Block PUT/DELETE at the reverse proxy for static content paths\n\
                     3. Patch to Tomcat 7.0.81+, 8.5.23+, 9.0.1+ (CVE-2017-12617)",
                ));
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
