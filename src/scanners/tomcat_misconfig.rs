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
            "/manager/text",
            "/host-manager/html",
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

        // Test 5: Sensitive Tomcat configuration files / artifacts.
        //
        // Tomcat ships a handful of files that should never be web-reachable but
        // routinely are when ROOT.war is mis-deployed, the work/ directory is
        // mounted under the docroot, or a reverse proxy passes everything to
        // /catalina-base/conf/. Each entry below requires a structural marker
        // unique to that file so a 200 with random JSON cannot trigger it.
        //
        // (path, label, severity, body_markers — at least one must match)
        let sensitive_files: &[(&str, &str, Severity, f32, &[&str])] = &[
            // tomcat-users.xml — contains plaintext / hashed manager creds.
            (
                "/tomcat-users.xml",
                "Tomcat Users Configuration (credentials)",
                Severity::Critical,
                9.8,
                &["<tomcat-users", "<user username=", "<role rolename="],
            ),
            (
                "/conf/tomcat-users.xml",
                "Tomcat Users Configuration (credentials)",
                Severity::Critical,
                9.8,
                &["<tomcat-users", "<user username=", "<role rolename="],
            ),
            (
                "/META-INF/tomcat-users.xml",
                "Tomcat Users Configuration (credentials)",
                Severity::Critical,
                9.8,
                &["<tomcat-users", "<user username="],
            ),
            // server.xml — full connector / Realm config including DB JDBC creds.
            (
                "/server.xml",
                "Tomcat server.xml Exposure",
                Severity::Critical,
                9.1,
                &["<Server port=", "<Service name=", "<Engine name=\"Catalina\""],
            ),
            (
                "/conf/server.xml",
                "Tomcat server.xml Exposure",
                Severity::Critical,
                9.1,
                &["<Server port=", "<Service name=", "<Engine name=\"Catalina\""],
            ),
            // context.xml — often holds JDBC Resource definitions with creds.
            (
                "/conf/context.xml",
                "Tomcat context.xml Exposure",
                Severity::High,
                7.5,
                &["<Context", "<Resource", "javax.sql.DataSource"],
            ),
            (
                "/META-INF/context.xml",
                "Tomcat META-INF/context.xml Exposure",
                Severity::High,
                7.5,
                &["<Context", "<Resource", "javax.sql.DataSource"],
            ),
            // web.xml — leaks servlet routes, security constraints, filter chain.
            (
                "/WEB-INF/web.xml",
                "Tomcat WEB-INF/web.xml Exposure",
                Severity::High,
                7.5,
                &[
                    "<web-app",
                    "<servlet-name>",
                    "<servlet-mapping>",
                    "<security-constraint>",
                ],
            ),
            (
                "/conf/web.xml",
                "Tomcat conf/web.xml Exposure",
                Severity::Medium,
                5.3,
                &["<web-app", "<servlet-name>"],
            ),
            // catalina.policy — full SecurityManager grants; reveals app paths.
            (
                "/conf/catalina.policy",
                "Tomcat catalina.policy Exposure",
                Severity::Medium,
                5.3,
                &["grant codeBase", "permission java.", "catalina.home"],
            ),
            // catalina.properties — JVM property + shared loader paths.
            (
                "/conf/catalina.properties",
                "Tomcat catalina.properties Exposure",
                Severity::Medium,
                5.3,
                &[
                    "common.loader=",
                    "shared.loader=",
                    "tomcat.util.scan.StandardJarScanFilter",
                ],
            ),
            // logging.properties — handler classpaths, log file locations.
            (
                "/conf/logging.properties",
                "Tomcat logging.properties Exposure",
                Severity::Low,
                3.7,
                &[
                    "java.util.logging",
                    "org.apache.juli.AsyncFileHandler",
                    "1catalina.org.apache.juli",
                ],
            ),
            // jmxremote — IF reachable, full JMX over HTTP/RMI is critical.
            (
                "/conf/jmxremote.password",
                "Tomcat JMX Remote Password File",
                Severity::Critical,
                9.8,
                &["monitorRole", "controlRole"],
            ),
            (
                "/conf/jmxremote.access",
                "Tomcat JMX Remote Access File",
                Severity::High,
                7.5,
                &["monitorRole", "controlRole", "readonly", "readwrite"],
            ),
            // setenv.sh / setenv.bat — JVM args, often containing -D secrets.
            (
                "/bin/setenv.sh",
                "Tomcat setenv.sh Exposure",
                Severity::High,
                7.5,
                &["CATALINA_OPTS", "JAVA_OPTS", "export "],
            ),
            (
                "/bin/setenv.bat",
                "Tomcat setenv.bat Exposure",
                Severity::High,
                7.5,
                &["CATALINA_OPTS", "JAVA_OPTS", "set "],
            ),
            // Status servlet — reveals JVM internals, thread dumps, sessions.
            (
                "/manager/status",
                "Tomcat Manager Status Servlet",
                Severity::High,
                7.5,
                &[
                    "Server Status",
                    "JVM",
                    "Max threads:",
                    "Manager Status",
                ],
            ),
            (
                "/manager/status?XML=true",
                "Tomcat Manager Status XML",
                Severity::High,
                7.5,
                &["<status>", "<jvm>", "<connector ", "<memory "],
            ),
            (
                "/manager/jmxproxy/?qry=*:*",
                "Tomcat JMX Proxy Servlet (unauthenticated)",
                Severity::Critical,
                9.8,
                &[
                    "Catalina:type=Server",
                    "Tomcat:type=",
                    "java.lang:type=",
                ],
            ),
            // CGI servlet examples — Tomcat ships a test cgi-bin that's RCE-y.
            (
                "/cgi-bin/test-cgi",
                "Tomcat CGI Test Script Exposed",
                Severity::High,
                7.5,
                &["CGI/1.1", "SERVER_SOFTWARE", "Apache Tomcat"],
            ),
            // Common WAR backup leaks.
            (
                "/ROOT.war",
                "Tomcat ROOT.war Backup Exposure",
                Severity::Critical,
                9.1,
                &["PK\x03\x04"],
            ),
            (
                "/manager.war",
                "Tomcat manager.war Exposure",
                Severity::Critical,
                9.1,
                &["PK\x03\x04"],
            ),
            // Work directory — JSP compilation artefacts (source-level leak).
            (
                "/work/Catalina/localhost/",
                "Tomcat Work Directory Listing",
                Severity::Medium,
                5.3,
                &["Directory: /work", "Index of /work", "_jsp.java", "_jsp.class"],
            ),
            // ServerInfo properties — exact build / OS / JVM strings.
            (
                "/org/apache/catalina/util/ServerInfo.properties",
                "Tomcat ServerInfo Properties Disclosed",
                Severity::Low,
                3.7,
                &["server.info=", "server.number=", "server.built="],
            ),
        ];

        for (path, label, severity, cvss, markers) in sensitive_files {
            tests_run += 1;
            let probe_url = format!("{}{}", url.trim_end_matches('/'), path);

            let Ok(response) = self.http_client.get(&probe_url).await else {
                continue;
            };
            if response.status_code != 200 {
                continue;
            }
            // Trim & cap to keep marker search cheap.
            let body = response.body.as_str();
            if body.is_empty() {
                continue;
            }
            // Require at least one structural marker — this is what keeps the
            // false-positive rate at zero for friendly 200-on-everything servers.
            let hit_marker = markers.iter().find(|m| body.contains(**m));
            let Some(marker) = hit_marker else { continue };

            info!(
                "Sensitive Tomcat resource exposed at {} (marker: {:?})",
                probe_url, marker
            );
            vulnerabilities.push(self.create_vulnerability(
                &probe_url,
                "TOMCAT_SENSITIVE_RESOURCE",
                &format!("{} accessible at {}", label, path),
                &format!(
                    "Path: {}\nStatus: 200\nMatched marker: {:?}\nSize: {} bytes",
                    path,
                    marker,
                    body.len()
                ),
                severity.clone(),
                Confidence::High,
                *cvss,
                "1. Block access to Tomcat internal directories at the reverse proxy / WAF.\n\
                 2. Remove backup WARs and stray config files from the docroot.\n\
                 3. Restrict manager/jmxproxy with RemoteAddrValve to internal IPs only.\n\
                 4. Ensure conf/ and bin/ are outside CATALINA_BASE/webapps.\n\
                 5. Rotate any credentials / DB strings that were exposed.",
            ));
        }

        // Test 6: AJP Protocol Exposure (Ghostcat CVE-2020-1938)
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
