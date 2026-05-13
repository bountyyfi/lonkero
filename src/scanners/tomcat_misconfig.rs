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
            "/host-manager/text",
            "/admin/",
            "/tomcat-admin/",
            // JMX over HTTP - allows reading/writing JMX MBeans (heap dumps, env vars, threads)
            "/manager/jmxproxy",
            "/manager/jmxproxy/?qry=java.lang:type=Memory",
            // XML status dump — leaks deployed apps, sessions, JVM info, connectors
            "/manager/status/all?XML=true",
            "/manager/text/list",
            "/manager/text/sessions",
            "/manager/text/threaddump",
            "/manager/text/vminfo",
            // Legacy JBoss/EAP JMX console paths sometimes co-deployed with Tomcat
            "/jmx-console/",
            "/web-console/",
            "/invoker/JMXInvokerServlet",
        ];

        for path in &manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for manager login page or accessible manager.
                    // Require Tomcat-specific content, not generic "401 unauthorized" text.
                    // Each marker is a string that ONLY the Tomcat Manager / JMX proxy returns,
                    // so a match is high-confidence and rarely produces false positives.
                    let is_manager = body_lower.contains("tomcat web application manager")
                        || body_lower.contains("tomcat virtual host manager")
                        || body_lower.contains("manager-gui")
                        // /manager/text/* responds with plaintext starting with "OK - "
                        || (path.contains("/manager/text/")
                            && response.status_code == 200
                            && response.body.starts_with("OK - "))
                        // /manager/status/all?XML=true responds with XML status root element
                        || (path.contains("XML=true")
                            && response.status_code == 200
                            && (response.body.contains("<status>")
                                || response.body.contains("<jvm>")
                                || response.body.contains("<connector ")))
                        // /manager/jmxproxy responds with "OK - Number of results: N" and MBean ObjectNames
                        || (path.contains("/manager/jmxproxy")
                            && response.status_code == 200
                            && (response.body.contains("OK - Number of results:")
                                || response.body.contains("Name: java.lang:type=")))
                        // JBoss JMX console (often co-deployed historically) — explicit marker
                        || (path.contains("/jmx-console/")
                            && response.status_code == 200
                            && body_lower.contains("jboss")
                            && body_lower.contains("jmx mbeans"))
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

        // Test 5: WEB-INF / META-INF leak via path normalization or reverse proxy
        //
        // Tomcat protects /WEB-INF and /META-INF, but a fronting reverse proxy or
        // misconfigured servlet mapping can leak deployment descriptors. We only flag
        // if the body actually contains the expected file's structural markers, which
        // are unique enough to eliminate false positives on generic 200 OK responses.
        tests_run += 1;
        let webinf_targets: &[(&str, &[&str], &str, Severity, f32)] = &[
            (
                "/WEB-INF/web.xml",
                &["<web-app", "<servlet-mapping", "<servlet-name"],
                "WEB-INF/web.xml deployment descriptor",
                Severity::High,
                7.5,
            ),
            (
                "/WEB-INF/classes/application.properties",
                &["spring.", "datasource.", "server.port="],
                "WEB-INF/classes/application.properties (Spring)",
                Severity::High,
                7.5,
            ),
            (
                "/WEB-INF/classes/log4j.properties",
                &["log4j.rootLogger", "log4j.appender."],
                "WEB-INF/classes/log4j.properties",
                Severity::Medium,
                5.3,
            ),
            (
                "/WEB-INF/classes/log4j2.xml",
                &["<Configuration", "<Appenders"],
                "WEB-INF/classes/log4j2.xml",
                Severity::Medium,
                5.3,
            ),
            (
                "/META-INF/context.xml",
                &["<Context", "<Resource "],
                "META-INF/context.xml (may contain DB credentials)",
                Severity::High,
                7.5,
            ),
            (
                "/META-INF/MANIFEST.MF",
                &["Manifest-Version:", "Implementation-Title:"],
                "META-INF/MANIFEST.MF (reveals build/version metadata)",
                Severity::Low,
                3.7,
            ),
            (
                "/WEB-INF/classes/META-INF/persistence.xml",
                &["<persistence", "<persistence-unit"],
                "JPA persistence.xml (may contain JDBC URL/credentials)",
                Severity::High,
                7.5,
            ),
        ];

        for (path, markers, label, severity, cvss) in webinf_targets {
            tests_run += 1;
            let leak_url = format!("{}{}", url.trim_end_matches('/'), path);
            match self.http_client.get(&leak_url).await {
                Ok(response) => {
                    if response.status_code == 200
                        && markers.iter().all(|m| response.body.contains(m))
                    {
                        info!("Tomcat {} leak at {}", label, leak_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &leak_url,
                            "TOMCAT_WEBINF_LEAK",
                            &format!("Tomcat Deployment File Leak: {}", label),
                            &format!(
                                "Protected file is fetchable via HTTP, indicating a path-normalization\n\
                                 or reverse-proxy bypass of Tomcat's WEB-INF/META-INF protection.\n\
                                 Path: {}\nStatus: {}\nMarkers matched: {:?}",
                                path, response.status_code, markers
                            ),
                            severity.clone(),
                            Confidence::High,
                            *cvss,
                            "1. Verify Tomcat is not directly serving WEB-INF/META-INF (check `<security-constraint>`).\n\
                             2. Audit any fronting proxy (nginx/Apache/F5) for path-normalization issues\n\
                                that strip `/WEB-INF` before forwarding. Disable `merge_slashes off` or similar\n\
                                rewrites that allow `..;/WEB-INF/...`.\n\
                             3. Rotate any credentials that may have been exposed via the leaked file.\n\
                             4. Move secrets out of property files into environment variables or a secret manager.",
                        ));
                    }
                }
                Err(e) => debug!("WEB-INF check failed for {}: {}", leak_url, e),
            }
        }

        // Test 6: RELEASE-NOTES.txt / changelog version disclosure (high confidence,
        // strict regex on the canonical "Apache Tomcat Version X.Y.Z" header)
        tests_run += 1;
        let release_notes_paths = vec![
            "/docs/RELEASE-NOTES.txt",
            "/docs/changelog.html",
            "/RELEASE-NOTES.txt",
        ];
        for path in &release_notes_paths {
            tests_run += 1;
            let rn_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&rn_url).await {
                if response.status_code == 200 {
                    if let Ok(re) =
                        regex::Regex::new(r"Apache Tomcat\s+Version\s+(\d+\.\d+\.\d+)")
                    {
                        if let Some(caps) = re.captures(&response.body) {
                            if let Some(version) = caps.get(1) {
                                vulnerabilities.push(self.create_vulnerability(
                                    &rn_url,
                                    "TOMCAT_RELEASE_NOTES_EXPOSED",
                                    &format!(
                                        "Tomcat RELEASE-NOTES Exposed (Version {})",
                                        version.as_str()
                                    ),
                                    &format!(
                                        "Tomcat docs/release-notes accessible at {} (version {}).\nAttackers can cross-reference exact version against public CVEs.",
                                        path, version.as_str()
                                    ),
                                    Severity::Low,
                                    Confidence::High,
                                    3.7,
                                    "1. Remove $CATALINA_HOME/webapps/docs in production.\n\
                                     2. Configure a Valve/WAF to block /docs/ from external access.",
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Test 7: AJP Protocol Exposure (Ghostcat CVE-2020-1938)
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
