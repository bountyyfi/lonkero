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

        // Test 2: Tomcat Manager / JMX / Admin Console Exposure
        //
        // Each path is paired with the minimum unique substring its real response
        // contains. A bare 200 or 401 with no Tomcat-specific marker is never enough
        // — we only report when the body proves it's the real component.
        tests_run += 1;
        let manager_paths: &[(&str, &[&str])] = &[
            // Web Application Manager (Catalina manager webapp)
            (
                "/manager/html",
                &[
                    "Tomcat Web Application Manager",
                    "<title>/manager</title>",
                ],
            ),
            ("/manager/status", &["Tomcat Web Application Manager", "Server Status"]),
            // /manager/text is the script API: GET /manager/text/list returns "OK -" prefix
            ("/manager/text", &["OK - Listed applications", "FAIL - "]),
            ("/manager/text/list", &["OK - Listed applications", "FAIL - "]),
            ("/manager/text/serverinfo", &["Tomcat Version:", "OS Name:", "JVM Version:"]),
            ("/manager/text/threaddump", &["OK - JVM thread dump", "java.lang.Thread.State"]),
            ("/manager/text/sslConnectorCiphers", &["OK - Connector / SSL", "Ciphers for"]),
            ("/manager/text/findleaks", &["OK - Found memory leaks", "OK - No memory leaks"]),
            ("/manager/text/vminfo", &["OK - VM info", "VM Vendor:"]),
            // Host Manager (vhost management)
            (
                "/host-manager/html",
                &["Tomcat Virtual Host Manager", "<title>/host-manager</title>"],
            ),
            ("/host-manager/text", &["FAIL - ", "OK - "]),
            ("/host-manager/text/list", &["OK - Listed hosts", "FAIL - "]),
            // JMX proxy servlet inside the manager webapp — direct RCE primitive
            (
                "/manager/jmxproxy",
                &["OK - Number of results", "MBean Names:", "Catalina:type="],
            ),
            (
                "/manager/jmxproxy/?qry=Catalina%3Atype%3DServer",
                &["Catalina:type=Server", "modelerType"],
            ),
            // JBoss / Tomcat-derivative JMX consoles often deployed alongside
            ("/jmx-console/", &["JMX Console", "HtmlAdaptor"]),
            ("/jmx-console/HtmlAdaptor", &["HtmlAdaptor", "jboss.system"]),
            ("/web-console/", &["JBoss Management Console", "Web Console"]),
            ("/web-console/Invoker", &["MarshalledInvocation", "InvokerServlet"]),
            // Legacy Tomcat admin webapp (removed in 6+, still seen on appliances)
            ("/admin/", &["<title>Tomcat", "Tomcat Administration Tool"]),
            ("/tomcat-admin/", &["<title>Tomcat", "Tomcat Administration Tool"]),
            // Coyote / catalina status JSP
            ("/status", &["Tomcat Web Application Manager", "Server Status"]),
            ("/status/all", &["MaxThreads:", "RequestCount:", "Catalina"]),
        ];

        for (path, signatures) in manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body = &response.body;
                    let body_lower = body.to_lowercase();

                    // Primary: any of the path-specific markers in the body.
                    let has_signature = signatures.iter().any(|s| body.contains(s));

                    // Secondary path-agnostic markers used for legacy /admin variants
                    // and for protected (401/403) responses that still leak Tomcat identity.
                    let is_manager_protected = matches!(response.status_code, 401 | 403)
                        && (body_lower.contains("tomcat")
                            || body_lower.contains("catalina"))
                        && (body_lower.contains("manager")
                            || body_lower.contains("host-manager")
                            || body_lower.contains("jmx"));

                    if !has_signature && !is_manager_protected {
                        continue;
                    }

                    let (severity, cvss) = match (response.status_code, has_signature) {
                        // Live, unauthenticated /jmxproxy or /text endpoints are RCE-class
                        (200, true) if path.contains("jmxproxy") => (Severity::Critical, 9.8),
                        (200, true) if path.contains("/text") => (Severity::Critical, 9.8),
                        (200, true) => (Severity::Critical, 9.8),
                        // Reachable but auth-gated — still high-value recon
                        (401, _) | (403, _) => (Severity::Medium, 5.3),
                        _ => (Severity::Low, 3.7),
                    };

                    info!("Tomcat manager-class interface found at {}", manager_url);
                    vulnerabilities.push(self.create_vulnerability(
                        &manager_url,
                        "TOMCAT_MANAGER_EXPOSED",
                        &format!("Tomcat Manager Interface Exposed at {}", path),
                        &format!(
                            "Manager interface reachable. Status: {}\nPath: {}\nMatched signature: {}",
                            response.status_code,
                            path,
                            has_signature
                        ),
                        severity,
                        Confidence::High,
                        cvss,
                        "1. Restrict manager access by IP in META-INF/context.xml:\n\
                            <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.0\\.0\\.1|192\\.168\\..+\"/>\n\
                         2. Use strong, unique credentials for manager accounts\n\
                         3. Remove the manager/host-manager/admin webapps in production\n\
                         4. Disable the JMX proxy servlet by removing it from manager web.xml\n\
                         5. Bind management UIs to localhost or an internal network only\n\
                         6. Enable SSL/TLS for any management access",
                    ));
                    // Continue scanning other manager paths — different paths reveal
                    // different attack surface (e.g. /text vs /jmxproxy).
                }
                Err(e) => {
                    debug!("Manager check failed for {}: {}", manager_url, e);
                }
            }
        }

        // Test 2b: Sensitive Tomcat configuration / deployment artifacts.
        //
        // These are file paths that are NEVER intentionally web-exposed on a
        // properly configured Tomcat. A 200 with the file's distinctive markup
        // is unambiguous evidence of misconfiguration.
        let sensitive_files: &[(&str, &str, &[&str], Severity)] = &[
            // WEB-INF and META-INF should be blocked by the default servlet
            (
                "/WEB-INF/web.xml",
                "WEB-INF/web.xml exposed",
                &["<web-app", "<servlet-mapping", "<servlet-name>"],
                Severity::High,
            ),
            (
                "/WEB-INF/classes/application.properties",
                "Application properties leaked via WEB-INF",
                &["spring.", "datasource", "password", "jdbc:"],
                Severity::Critical,
            ),
            (
                "/WEB-INF/classes/application.yml",
                "Application YAML leaked via WEB-INF",
                &["datasource:", "password:", "jdbc:"],
                Severity::Critical,
            ),
            (
                "/WEB-INF/classes/log4j.properties",
                "log4j config leaked via WEB-INF",
                &["log4j.rootLogger", "log4j.appender"],
                Severity::Medium,
            ),
            (
                "/WEB-INF/classes/log4j2.xml",
                "log4j2 config leaked via WEB-INF",
                &["<Configuration", "<Appenders", "log4j"],
                Severity::Medium,
            ),
            (
                "/META-INF/context.xml",
                "META-INF/context.xml exposed",
                &["<Context", "<Resource", "<Valve"],
                Severity::High,
            ),
            (
                "/META-INF/MANIFEST.MF",
                "META-INF/MANIFEST.MF exposed",
                &["Manifest-Version:", "Implementation-"],
                Severity::Low,
            ),
            // tomcat-users.xml is the credential file — full takeover if leaked
            (
                "/conf/tomcat-users.xml",
                "tomcat-users.xml exposed",
                &["<tomcat-users", "<user ", "password="],
                Severity::Critical,
            ),
            (
                "/conf/server.xml",
                "server.xml exposed",
                &["<Server ", "<Service ", "<Connector "],
                Severity::Critical,
            ),
            (
                "/conf/web.xml",
                "Tomcat global web.xml exposed",
                &["<web-app", "default", "DefaultServlet"],
                Severity::High,
            ),
            (
                "/conf/catalina.policy",
                "catalina.policy exposed",
                &["grant codeBase", "permission java."],
                Severity::Medium,
            ),
            (
                "/conf/context.xml",
                "Global context.xml exposed",
                &["<Context", "<WatchedResource"],
                Severity::Medium,
            ),
            // Backup / build artifacts left in webapps
            (
                "/WEB-INF/web.xml.bak",
                "Backup web.xml exposed",
                &["<web-app", "<servlet"],
                Severity::High,
            ),
            (
                "/WEB-INF/web.xml.old",
                "Old web.xml exposed",
                &["<web-app", "<servlet"],
                Severity::High,
            ),
            (
                "/WEB-INF/web.xml~",
                "Editor-backup web.xml exposed",
                &["<web-app", "<servlet"],
                Severity::High,
            ),
            // CGI / SSI servlets — historical RCE primitives if mapped
            (
                "/cgi-bin/",
                "Tomcat CGI servlet enabled",
                &["Index of /cgi-bin", "<title>Directory"],
                Severity::Medium,
            ),
            // Apache mod_status reverse-proxied from Tomcat
            (
                "/server-status",
                "mod_status (or Tomcat status) reachable",
                &["Apache Server Status", "Server Version:", "Tomcat"],
                Severity::Medium,
            ),
            (
                "/server-info",
                "mod_info reachable",
                &["Apache Server Information", "Module Name:"],
                Severity::Medium,
            ),
        ];

        for (path, label, signatures, severity) in sensitive_files {
            tests_run += 1;
            let probe_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&probe_url).await {
                Ok(response) => {
                    if response.status_code != 200 || response.body.len() < 12 {
                        continue;
                    }
                    let body = &response.body;
                    let has_signature = signatures.iter().any(|s| body.contains(s));
                    if !has_signature {
                        continue;
                    }

                    let cvss = match severity {
                        Severity::Critical => 9.1,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.7,
                    };

                    info!("Sensitive Tomcat artifact exposed at {}", probe_url);
                    vulnerabilities.push(self.create_vulnerability(
                        &probe_url,
                        "TOMCAT_SENSITIVE_FILE_EXPOSED",
                        label,
                        &format!(
                            "Path: {}\nStatus: 200\nMatched signature inside response body confirms the real file contents are being served.",
                            path
                        ),
                        severity.clone(),
                        Confidence::High,
                        cvss,
                        "1. Block WEB-INF and META-INF in the default servlet (Tomcat does this by default — re-check any custom valve/filter ordering or front-proxy rewrites)\n\
                         2. Move backup files (*.bak, *.old, *~) out of the deployed webapp\n\
                         3. Remove /conf from any reverse-proxy alias that maps Catalina's filesystem\n\
                         4. Rotate any credentials that appear in tomcat-users.xml, server.xml, or application.properties\n\
                         5. Disable the CGI/SSI servlets in conf/web.xml unless explicitly required",
                    ));
                }
                Err(e) => {
                    debug!("Sensitive-file probe failed for {}: {}", probe_url, e);
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
