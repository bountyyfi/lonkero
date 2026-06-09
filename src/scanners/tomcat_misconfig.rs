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

        // Test 6: Sensitive Tomcat / Spring-Boot configuration & log file disclosure.
        //
        // Each path is anchored to a content fingerprint unique to the real file —
        // a generic 200 OK with any HTML is NOT enough to fire. This keeps the
        // signal-to-noise ratio extremely high on real targets.
        //
        // Severity tiers:
        //   Critical : tomcat-users.xml, context.xml  (live credentials likely)
        //   High     : web.xml, server.xml            (deployment / connector secrets)
        //   Medium   : catalina.policy, log files      (paths, IPs, stack traces)
        tests_run += 1;
        let sensitive_files: Vec<(&str, &str)> = vec![
            ("/WEB-INF/web.xml", "Tomcat web.xml deployment descriptor"),
            ("/WEB-INF/classes/application.properties", "Spring Boot application.properties"),
            ("/WEB-INF/classes/application.yml", "Spring Boot application.yml"),
            ("/WEB-INF/classes/application-dev.properties", "Spring Boot dev profile properties"),
            ("/WEB-INF/classes/application-prod.properties", "Spring Boot prod profile properties"),
            ("/WEB-INF/classes/log4j.properties", "log4j configuration"),
            ("/WEB-INF/classes/logback.xml", "logback configuration"),
            ("/META-INF/context.xml", "Tomcat context.xml (may contain DB credentials)"),
            ("/META-INF/MANIFEST.MF", "JAR manifest"),
            ("/conf/tomcat-users.xml", "Tomcat user/role definitions"),
            ("/conf/server.xml", "Tomcat server.xml configuration"),
            ("/conf/catalina.policy", "Tomcat security policy"),
            ("/conf/catalina.properties", "Tomcat catalina.properties"),
            ("/conf/web.xml", "Tomcat default web.xml"),
            ("/conf/context.xml", "Tomcat global context.xml"),
            ("/conf/logging.properties", "Tomcat logging configuration"),
            ("/logs/catalina.out", "Tomcat main log file"),
            ("/logs/manager.log", "Tomcat manager log"),
            ("/logs/host-manager.log", "Tomcat host-manager log"),
            ("/logs/localhost_access_log.txt", "Tomcat access log"),
        ];

        // Pre-compile the access log regex once.
        let access_log_re =
            regex::Regex::new(r#"\d+\.\d+\.\d+\.\d+ \S+ \S+ \[\d+/\w+/\d{4}"#).ok();

        for (path, desc) in &sensitive_files {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code != 200 || response.body.is_empty() {
                        continue;
                    }
                    let body = &response.body;
                    let body_lower = body.to_lowercase();

                    // Soft-block error pages that some servers return with 200.
                    if body_lower.contains("<title>404")
                        || body_lower.contains("not found</title>")
                        || body_lower.contains("access denied")
                    {
                        continue;
                    }

                    let confirmed = match *path {
                        "/WEB-INF/web.xml" | "/conf/web.xml" => {
                            body.contains("<web-app")
                                && (body_lower.contains("<servlet")
                                    || body_lower.contains("<filter")
                                    || body_lower.contains("<security-constraint"))
                        }
                        "/META-INF/context.xml" | "/conf/context.xml" => {
                            body.contains("<Context")
                                && (body_lower.contains("<resource")
                                    || body_lower.contains("<realm")
                                    || body_lower.contains("<valve"))
                        }
                        "/conf/tomcat-users.xml" => {
                            body.contains("<tomcat-users")
                                && (body_lower.contains("<user ")
                                    || body_lower.contains("<role "))
                        }
                        "/conf/server.xml" => {
                            body.contains("<Server") && body_lower.contains("<connector")
                        }
                        "/conf/catalina.policy" => {
                            body.contains("grant codeBase") && body.contains("permission")
                        }
                        "/conf/catalina.properties" => {
                            body_lower.contains("common.loader=")
                                || body_lower.contains("server.loader=")
                                || body_lower.contains("shared.loader=")
                        }
                        "/conf/logging.properties" => {
                            body_lower.contains("handlers=")
                                && body_lower.contains("java.util.logging")
                        }
                        "/META-INF/MANIFEST.MF" => {
                            body.starts_with("Manifest-Version:")
                                || body.contains("Manifest-Version: 1.0")
                        }
                        "/WEB-INF/classes/application.properties"
                        | "/WEB-INF/classes/application-dev.properties"
                        | "/WEB-INF/classes/application-prod.properties" => {
                            body_lower.contains("spring.")
                                || body_lower.contains("server.port=")
                                || body_lower.contains("datasource.")
                                || body_lower.contains("logging.level")
                        }
                        "/WEB-INF/classes/application.yml" => {
                            (body_lower.contains("spring:")
                                || body_lower.contains("server:"))
                                && body.contains(':')
                        }
                        "/WEB-INF/classes/log4j.properties" => {
                            body_lower.contains("log4j.rootlogger")
                                || body_lower.contains("log4j.appender")
                        }
                        "/WEB-INF/classes/logback.xml" => {
                            body.contains("<configuration")
                                && (body_lower.contains("<appender")
                                    || body_lower.contains("<logger"))
                        }
                        "/logs/catalina.out"
                        | "/logs/manager.log"
                        | "/logs/host-manager.log" => {
                            body_lower.contains("org.apache.catalina")
                                || body_lower.contains("starting service")
                                || body.contains("INFO [")
                                || body.contains("SEVERE [")
                        }
                        "/logs/localhost_access_log.txt" => access_log_re
                            .as_ref()
                            .map(|r| r.is_match(body))
                            .unwrap_or(false),
                        _ => false,
                    };

                    if !confirmed {
                        continue;
                    }

                    let (severity, cvss) = match *path {
                        "/conf/tomcat-users.xml"
                        | "/META-INF/context.xml"
                        | "/conf/context.xml" => (Severity::Critical, 9.0),
                        "/WEB-INF/web.xml"
                        | "/conf/web.xml"
                        | "/conf/server.xml"
                        | "/WEB-INF/classes/application.properties"
                        | "/WEB-INF/classes/application-dev.properties"
                        | "/WEB-INF/classes/application-prod.properties"
                        | "/WEB-INF/classes/application.yml" => (Severity::High, 7.5),
                        _ => (Severity::Medium, 5.3),
                    };

                    // Trim a preview so the evidence is useful but bounded.
                    let preview: String = body.chars().take(240).collect();

                    info!(
                        "Tomcat sensitive file disclosed at {} ({})",
                        test_url, desc
                    );
                    vulnerabilities.push(self.create_vulnerability(
                        &test_url,
                        "TOMCAT_SENSITIVE_FILE_DISCLOSURE",
                        &format!("Tomcat Sensitive File Disclosure: {}", path),
                        &format!(
                            "{} accessible without authentication at {}.\nFingerprint: matched expected file structure.\nFirst 240 chars:\n{}",
                            desc, path, preview
                        ),
                        severity,
                        Confidence::High,
                        cvss,
                        "1. Block direct access to /WEB-INF, /META-INF, /conf, /logs at the reverse proxy.\n\
                         2. Tomcat's default servlet rejects /WEB-INF — if these paths are served, the\n\
                            fronting proxy (nginx/Apache/IIS) is misrouting or path normalization is off.\n\
                         3. If tomcat-users.xml or context.xml are exposed, rotate every credential they\n\
                            contain immediately (DB passwords, manager creds, realm secrets).\n\
                         4. Move log files outside the deployable webapp directory; never publish /logs.\n\
                         5. Re-deploy with <security-constraint> on /WEB-INF/* and /META-INF/* in web.xml\n\
                            and verify with `curl -I .../WEB-INF/web.xml` that the response is 404."
                    ));
                    // One finding per scan is enough — the remediation is the same and
                    // we don't want noise from multiple paths exposed by the same misconfig.
                    break;
                }
                Err(e) => {
                    debug!("Sensitive file check failed for {}: {}", test_url, e);
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
