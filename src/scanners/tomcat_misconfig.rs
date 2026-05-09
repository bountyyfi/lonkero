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
            "/manager/text/serverinfo",
            "/manager/text/sessions",
            "/manager/text/threaddump",
            "/manager/jmxproxy",
            "/manager/jmxproxy/?qry=Catalina:type=Manager,context=/manager,host=localhost",
            "/host-manager/html",
            "/host-manager/html/",
            "/host-manager/text",
            "/host-manager/text/list",
            "/admin/",
            "/admin/html",
            "/admin/html/",
            "/tomcat-admin/",
            "/tomcat/manager/html",
            "/tomcat/manager/status",
            // Common reverse-proxy mount points
            "/tomcat-manager/",
            "/manager/",
            "/web-console/",
            "/jmx-console/",
        ];

        for path in &manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for manager login page or accessible manager
                    // Require Tomcat-specific content, not generic "401 unauthorized" text.
                    // /manager/jmxproxy and /manager/text/* return plain-text 200 with
                    // very specific MBean / "OK -" prefixes that uniquely identify them.
                    let is_manager = body_lower.contains("tomcat web application manager")
                        || body_lower.contains("tomcat virtual host manager")
                        || body_lower.contains("manager-gui")
                        || body_lower.starts_with("ok - listed applications")
                        || body_lower.starts_with("ok - server info")
                        || body_lower.starts_with("ok - listed sessions")
                        || body_lower.starts_with("ok - listed virtual hosts")
                        || (path.contains("/jmxproxy") && body_lower.contains("name=catalina:"))
                        || (path.contains("/threaddump") && body_lower.contains("at org.apache.catalina"))
                        || (response.status_code == 401 && body_lower.contains("tomcat"))
                        || (response.status_code == 401
                            && response
                                .headers
                                .get("www-authenticate")
                                .or_else(|| response.headers.get("WWW-Authenticate"))
                                .map(|v| v.to_lowercase().contains("tomcat manager"))
                                .unwrap_or(false));

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

        // Test 4b: Psi-Probe (Lambda Probe) - third-party Tomcat admin tool
        // that exposes datasource passwords, app deployment, and JVM controls
        // *without* the Tomcat-manager role check. High-impact when found.
        tests_run += 1;
        let probe_paths = vec![
            "/probe/",
            "/probe/index.htm",
            "/probe/sessions.htm",
            "/probe/datasources.htm",
            "/probe/system.htm",
            "/probe/connectors.htm",
            "/probe/threads.htm",
            "/probe/deploy.htm",
            "/lambdaprobe/",
            "/lambdaprobe/index.htm",
        ];
        for path in &probe_paths {
            tests_run += 1;
            let probe_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&probe_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    // Probe-specific markers: page title and copyright string.
                    // These are unique enough that a generic SPA shell cannot
                    // match them by accident.
                    let is_probe = body_lower.contains("psi-probe")
                        || body_lower.contains("psi probe")
                        || body_lower.contains("lambda probe")
                        || body_lower.contains("href=\"sessions.htm\"")
                            && body_lower.contains("href=\"datasources.htm\"");
                    if is_probe {
                        info!("Psi-Probe / Lambda Probe interface accessible at {}", probe_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &probe_url,
                            "TOMCAT_PSI_PROBE_EXPOSED",
                            "Psi-Probe / Lambda Probe Tomcat Admin Interface Exposed",
                            &format!(
                                "Psi-Probe accessible. Path: {}\nThis tool exposes datasource passwords, JVM internals, app deploy/redeploy, and request tracing.",
                                path
                            ),
                            Severity::Critical,
                            Confidence::High,
                            9.1,
                            "1. Restrict /probe to internal networks via reverse proxy or firewall\n\
                             2. Configure Psi-Probe security in WEB-INF/web.xml with strong credentials\n\
                             3. Remove Psi-Probe entirely from production deployments\n\
                             4. Place behind VPN or zero-trust gateway",
                        ));
                        break;
                    }
                }
            }
        }

        // Test 4c: Apache server-status / server-info (mod_status front-fronting Tomcat)
        // Often forgotten on Apache reverse proxies that sit in front of Tomcat.
        tests_run += 1;
        let status_paths = vec![
            "/server-status",
            "/server-info",
            "/status",
            "/balancer-manager",
        ];
        for path in &status_paths {
            tests_run += 1;
            let status_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&status_url).await {
                if response.status_code == 200 {
                    let body = &response.body;
                    let body_lower = body.to_lowercase();
                    let is_server_status = match *path {
                        "/server-status" => body_lower.contains("apache server status")
                            || (body_lower.contains("server uptime")
                                && body_lower.contains("requests currently")),
                        "/server-info" => body_lower.contains("apache server information")
                            || body_lower.contains("server settings"),
                        "/status" => body_lower.contains("worker proxy:balancer")
                            || body_lower.contains("apache server status"),
                        "/balancer-manager" => body_lower.contains("load balancer manager")
                            || body_lower.contains("balancer://"),
                        _ => false,
                    };
                    if is_server_status {
                        info!("Apache mod_status endpoint accessible at {}", status_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &status_url,
                            "APACHE_SERVER_STATUS_EXPOSED",
                            &format!("Apache {} Endpoint Publicly Accessible", path),
                            &format!(
                                "{} discloses server internals (active workers, request URIs, vhosts).\nPath: {}",
                                path, path
                            ),
                            Severity::Medium,
                            Confidence::High,
                            5.3,
                            "1. Restrict access in httpd.conf:\n\
                                <Location /server-status>\n\
                                    SetHandler server-status\n\
                                    Require ip 127.0.0.1\n\
                                </Location>\n\
                             2. Disable mod_status on the public vhost\n\
                             3. Block at reverse proxy / WAF",
                        ));
                        break;
                    }
                }
            }
        }

        // Test 4d: WEB-INF / META-INF file disclosure
        // Tomcat normally blocks /WEB-INF/* with 404, but reverse-proxy
        // misconfigurations frequently expose these files. web.xml and
        // context.xml routinely contain datasource passwords and admin creds.
        tests_run += 1;
        let webinf_paths: &[(&str, &[&str])] = &[
            ("/WEB-INF/web.xml", &["<web-app", "<servlet-class>", "<filter-class>"]),
            ("/WEB-INF/web.xml.bak", &["<web-app", "<servlet-class>"]),
            ("/WEB-INF/web.xml.old", &["<web-app", "<servlet-class>"]),
            ("/WEB-INF/web.xml~", &["<web-app", "<servlet-class>"]),
            ("/WEB-INF/classes/application.properties", &["spring.datasource.", "server.port="]),
            ("/WEB-INF/classes/application.yml", &["spring:", "datasource:"]),
            ("/WEB-INF/classes/log4j.properties", &["log4j.rootLogger", "log4j.appender."]),
            ("/WEB-INF/classes/log4j2.xml", &["<Configuration", "<Appenders>"]),
            ("/WEB-INF/classes/logback.xml", &["<configuration", "<appender"]),
            ("/WEB-INF/classes/hibernate.cfg.xml", &["<hibernate-configuration>", "<session-factory>"]),
            ("/WEB-INF/classes/struts.xml", &["<struts>", "<package "]),
            ("/WEB-INF/spring-config.xml", &["<beans", "http://www.springframework.org/schema/beans"]),
            ("/WEB-INF/applicationContext.xml", &["<beans", "http://www.springframework.org/schema/beans"]),
            ("/META-INF/context.xml", &["<Context", "<Resource ", "auth=\"Container\""]),
            ("/META-INF/MANIFEST.MF", &["Manifest-Version:", "Implementation-"]),
            ("/META-INF/persistence.xml", &["<persistence-unit", "javax.persistence"]),
            ("/META-INF/tomcat-users.xml", &["<tomcat-users>", "<user "]),
            ("/conf/tomcat-users.xml", &["<tomcat-users>", "<user "]),
            ("/conf/server.xml", &["<Server ", "<Service ", "<Connector "]),
            ("/conf/web.xml", &["<web-app", "<servlet-class>"]),
            ("/conf/catalina.properties", &["common.loader=", "shared.loader="]),
            // Catalina log files that often live in /logs/ when staticly served
            ("/logs/catalina.out", &["org.apache.catalina", "INFO ["]),
            ("/logs/localhost.log", &["org.apache.catalina"]),
            ("/logs/manager.log", &["org.apache.catalina.core"]),
            // Source disclosure via JSP suffix tricks
            ("/index.jsp.bak", &["<%@", "<jsp:"]),
            ("/index.jsp~", &["<%@", "<jsp:"]),
        ];
        for (path, signatures) in webinf_paths {
            tests_run += 1;
            let webinf_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&webinf_url).await {
                if response.status_code == 200 {
                    // Require at least two of the path-specific signatures so
                    // a 200 SPA shell cannot match.
                    let hits = signatures
                        .iter()
                        .filter(|sig| response.body.contains(*sig))
                        .count();
                    if hits >= 2 || (signatures.len() == 1 && hits == 1) {
                        // Severity escalates if the file is known to carry
                        // credentials.
                        let has_creds = response.body.contains("password")
                            || response.body.contains("Password")
                            || response.body.contains("PASSWORD")
                            || response.body.contains("auth=\"Container\"")
                            || response.body.contains("connectionURL")
                            || response.body.contains("jdbc:");
                        let severity = if has_creds {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        let cvss = if has_creds { 9.1 } else { 7.5 };
                        info!("Tomcat sensitive file exposed: {}", webinf_url);
                        vulnerabilities.push(self.create_vulnerability(
                            &webinf_url,
                            "TOMCAT_SENSITIVE_FILE_EXPOSED",
                            &format!("Tomcat Sensitive File Exposed: {}", path),
                            &format!(
                                "Internal Tomcat configuration file is web-accessible.\nPath: {}\nContains credentials: {}",
                                path, has_creds
                            ),
                            severity,
                            Confidence::High,
                            cvss,
                            "1. Block /WEB-INF/* and /META-INF/* at the reverse proxy:\n\
                                location ~ ^/(WEB-INF|META-INF)/ { return 404; }\n\
                             2. Remove .bak/.old/~ backup files from production webapps\n\
                             3. Verify Tomcat's default deny on these paths is not bypassed by URL normalization\n\
                             4. Rotate any credentials that may have been exposed",
                        ));
                        break;
                    }
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
