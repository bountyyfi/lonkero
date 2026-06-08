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
            "/manager/text/sslConnectorCiphers",
            "/manager/text/threaddump",
            "/manager/text/vminfo",
            "/manager/jmxproxy",
            "/manager/jmxproxy/?qry=Catalina%3Atype%3DServer",
            "/host-manager/html",
            "/host-manager/text",
            "/host-manager/text/list",
            "/admin/",
            "/admin/index.jsp",
            "/tomcat-admin/",
            "/jmx-console/",
            "/web-console/",
            "/invoker/",
            "/invoker/JMXInvokerServlet",
            "/balancer/",
            // Case-variation bypasses against URL canonicalisation flaws.
            "/Manager/Html",
            "/MANAGER/HTML",
            "/manager;jsessionid=x/html",
        ];

        for path in &manager_paths {
            tests_run += 1;
            let manager_url = format!("{}{}", url.trim_end_matches('/'), path);

            match self.http_client.get(&manager_url).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for manager login page or accessible manager
                    // Require Tomcat-specific content, not generic "401 unauthorized" text.
                    // /manager/text/* returns plain-text "OK - " or "FAIL - " prefixes that
                    // are unique to the text manager interface. /manager/jmxproxy returns
                    // "OK - Number of results: <n>" or a list of MBean attributes.
                    let is_text_manager_ok = response.status_code == 200
                        && (response.body.starts_with("OK - ")
                            || response.body.starts_with("FAIL - "));
                    let is_jmxproxy = response.status_code == 200
                        && (response.body.contains("Number of results")
                            || (response.body.contains("Catalina:")
                                && response.body.contains("=")));
                    let is_manager = body_lower.contains("tomcat web application manager")
                        || body_lower.contains("tomcat virtual host manager")
                        || body_lower.contains("manager-gui")
                        || body_lower.contains("manager-script")
                        || body_lower.contains("jmx proxy servlet")
                        || body_lower.contains("jboss management console")
                        || body_lower.contains("jboss web console")
                        || is_text_manager_ok
                        || is_jmxproxy
                        || (response.status_code == 401 && body_lower.contains("tomcat"))
                        || (response.status_code == 403 && body_lower.contains("tomcat"));

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

        // Test 4b: Server Status / Server Info (mod_status / probe / metrics)
        // These mirror the Tomcat/JBoss/WildFly admin surfaces and reveal vhosts,
        // deployed apps, JVM stats, request handlers, etc. We only flag when the
        // body has Tomcat-specific markers (server-status text "Tomcat" header,
        // /probe.war WildFly HTML, etc.) to avoid generic "/server-status" matches
        // on apache mod_status, which has its own scanner.
        tests_run += 1;
        let status_paths = vec![
            ("/server-status", "Apache mod_status / Tomcat status"),
            ("/server-info", "Apache mod_info / Tomcat info"),
            ("/probe/", "Lambda Probe / Psi Probe management UI"),
            ("/probe", "Lambda Probe / Psi Probe management UI"),
            ("/psi-probe/", "Psi Probe management UI"),
            ("/manager/jmxproxy/?get=Catalina%3Atype%3DServer&att=serverInfo", "Tomcat JMX Server attribute"),
            ("/host-manager/text/list", "Host Manager text list"),
        ];
        for (path, label) in &status_paths {
            tests_run += 1;
            let probe_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&probe_url).await {
                if response.status_code != 200 {
                    continue;
                }
                let body = &response.body;
                let body_lower = body.to_lowercase();
                // Signature-gated: require Tomcat-specific markers, not just word "status".
                let psi_probe = body_lower.contains("psi probe")
                    || body_lower.contains("lambdaprobe")
                    || (body_lower.contains("probe") && body_lower.contains("tomcat"));
                let jmx_attr = body.contains("Catalina:type=Server")
                    && (body.contains("serverInfo") || body.contains("Apache Tomcat"));
                let tomcat_status = body_lower.contains("apache tomcat")
                    && (body_lower.contains("jvm")
                        || body_lower.contains("threads")
                        || body_lower.contains("max threads")
                        || body_lower.contains("requestinfo")
                        || body_lower.contains("connector"));
                let host_list = response.body.starts_with("OK - ")
                    && body_lower.contains("host");
                if psi_probe || jmx_attr || tomcat_status || host_list {
                    let severity = if path.contains("jmxproxy") || psi_probe {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    let cvss = if path.contains("jmxproxy") || psi_probe { 7.5 } else { 5.3 };
                    vulnerabilities.push(self.create_vulnerability(
                        &probe_url,
                        "TOMCAT_STATUS_EXPOSED",
                        &format!("{} Exposed - Information Disclosure", label),
                        &format!(
                            "Tomcat / JBoss admin status surface accessible at {}.\nStatus: {}\nThis exposes JVM internals, request handlers, vhost lists, or JMX MBeans.",
                            path, response.status_code
                        ),
                        severity,
                        Confidence::High,
                        cvss,
                        "1. Restrict /server-status, /probe, and /manager/jmxproxy to internal IPs:\n   <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.0\\.0\\.1\"/>\n\
                         2. Remove Lambda Probe / Psi Probe in production deployments.\n\
                         3. Set the manager-jmx role only on accounts that need JMX read access.\n\
                         4. Front the host with a reverse proxy that drops these paths from the public surface.",
                    ));
                    break;
                }
            }
        }

        // Test 4c: WEB-INF / META-INF traversal-style direct disclosure.
        // CVE-2014-7810 / CVE-2018-1305 family — when the connector is misconfigured
        // or a reverse proxy doesn't strip these paths, the deployment descriptor
        // and built classes are served verbatim.
        tests_run += 1;
        let webinf_paths = vec![
            ("/WEB-INF/web.xml", Severity::High, 7.5),
            ("/WEB-INF/classes/application.properties", Severity::Critical, 9.1),
            ("/WEB-INF/classes/application.yml", Severity::Critical, 9.1),
            ("/WEB-INF/classes/config.properties", Severity::Critical, 9.1),
            ("/WEB-INF/classes/log4j.properties", Severity::Medium, 5.3),
            ("/WEB-INF/classes/log4j2.xml", Severity::Medium, 5.3),
            ("/WEB-INF/classes/logback.xml", Severity::Medium, 5.3),
            ("/WEB-INF/classes/hibernate.cfg.xml", Severity::Critical, 9.1),
            ("/WEB-INF/classes/META-INF/persistence.xml", Severity::High, 7.5),
            ("/META-INF/context.xml", Severity::High, 7.5),
            ("/META-INF/MANIFEST.MF", Severity::Low, 3.7),
            ("/META-INF/maven", Severity::Low, 3.7),
            // Reverse-proxy bypass variants:
            ("/%2e/WEB-INF/web.xml", Severity::High, 7.5),
            ("/.;/WEB-INF/web.xml", Severity::High, 7.5),
            ("//WEB-INF/web.xml", Severity::High, 7.5),
        ];
        for (path, severity, cvss) in &webinf_paths {
            tests_run += 1;
            let webinf_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&webinf_url).await {
                if response.status_code != 200 || response.body.len() < 40 {
                    continue;
                }
                let body = &response.body;
                let body_lower = body.to_lowercase();
                // Each path family needs its own deterministic signature.
                let matched = match *path {
                    p if p.contains("web.xml") => {
                        body_lower.contains("<web-app")
                            && (body_lower.contains("</web-app>")
                                || body_lower.contains("servlet-mapping")
                                || body_lower.contains("xmlns=\"http://java.sun.com/xml/ns/javaee\"")
                                || body_lower.contains("xmlns=\"https://jakarta.ee/xml/ns/jakartaee\""))
                    }
                    p if p.contains("context.xml") => {
                        body_lower.contains("<context") && body_lower.contains("</context>")
                    }
                    p if p.contains("application.properties") || p.contains("config.properties") => {
                        body.contains("=") && !body_lower.starts_with("<!doctype") && !body_lower.starts_with("<html")
                            && (body_lower.contains("password")
                                || body_lower.contains("jdbc:")
                                || body_lower.contains("spring.")
                                || body_lower.contains("server.port"))
                    }
                    p if p.contains("application.yml") => {
                        body.contains(":") && !body_lower.starts_with("<!doctype") && !body_lower.starts_with("<html")
                            && (body_lower.contains("password")
                                || body_lower.contains("jdbc:")
                                || body_lower.contains("spring:")
                                || body_lower.contains("server:"))
                    }
                    p if p.contains("log4j") || p.contains("logback") => {
                        body_lower.contains("appender")
                            || body_lower.contains("rootlogger")
                            || body_lower.contains("<configuration")
                    }
                    p if p.contains("hibernate.cfg.xml") => {
                        body_lower.contains("<hibernate-configuration")
                            || body_lower.contains("hibernate.connection")
                    }
                    p if p.contains("persistence.xml") => {
                        body_lower.contains("<persistence")
                            && body_lower.contains("persistence-unit")
                    }
                    p if p.contains("MANIFEST.MF") => {
                        body.starts_with("Manifest-Version:")
                            || (body.contains("Manifest-Version:")
                                && body.contains("Implementation-Title:"))
                    }
                    p if p.contains("/META-INF/maven") => {
                        body_lower.contains("pom.properties")
                            || body_lower.contains("pom.xml")
                            || (body_lower.contains("groupid=") && body_lower.contains("artifactid="))
                    }
                    _ => false,
                };
                if !matched {
                    continue;
                }
                vulnerabilities.push(self.create_vulnerability(
                    &webinf_url,
                    "TOMCAT_WEBINF_DISCLOSURE",
                    &format!("Tomcat {} Disclosed", path),
                    &format!(
                        "Servlet container's protected resource is publicly accessible.\nPath: {}\nStatus: 200\nBytes: {}",
                        path, response.body.len()
                    ),
                    severity.clone(),
                    Confidence::High,
                    *cvss,
                    "1. Ensure the connector / reverse proxy rejects requests to /WEB-INF/* and /META-INF/* paths.\n\
                     2. For Tomcat behind nginx/Apache: add `location ~* ^/(WEB-INF|META-INF)/ { deny all; }`.\n\
                     3. Check for CVE-2014-7810 / CVE-2018-1305 / CVE-2020-1938 patch level.\n\
                     4. Configure Tomcat to redirect `/.;/`, `/%2e/` and `//` path tricks (see CVE-2018-11784).",
                ));
                break;
            }
        }

        // Test 4d: CVE-2017-12615 — PUT-method JSP upload check (non-exploit).
        // We only check OPTIONS / a HEAD probe to see if the connector advertises
        // PUT; we never attempt to write a JSP. A confirmed-listed PUT method on a
        // Tomcat connector + readonly=false default servlet means RCE risk.
        tests_run += 1;
        match self.http_client.request_with_method("OPTIONS", url).await {
            Ok(response) => {
                let allow = response
                    .headers
                    .get("allow")
                    .or_else(|| response.headers.get("Allow"))
                    .cloned()
                    .unwrap_or_default();
                let allow_lower = allow.to_lowercase();
                let server_lower = response
                    .headers
                    .get("server")
                    .or_else(|| response.headers.get("Server"))
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                // Only flag when the Server header explicitly says Apache-Coyote / Tomcat
                // AND OPTIONS reports PUT/DELETE methods. Generic apps that mis-advertise
                // PUT (e.g. ASP.NET WebDAV) get their own dedicated scanner.
                let is_tomcat_server = server_lower.contains("apache-coyote")
                    || server_lower.contains("apache tomcat")
                    || server_lower.contains("tomcat");
                if is_tomcat_server
                    && (allow_lower.contains("put") || allow_lower.contains("delete"))
                {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "TOMCAT_PUT_METHOD_ENABLED",
                        "Tomcat Default Servlet Advertises PUT/DELETE - CVE-2017-12615 Risk",
                        &format!(
                            "Tomcat connector reports `Allow: {}` and Server header confirms Apache Coyote/Tomcat ({}).\nWhen Tomcat's DefaultServlet is configured with readonly=false, attackers can PUT .jsp / .jspx files for RCE (CVE-2017-12615).",
                            allow, server_lower
                        ),
                        Severity::High,
                        Confidence::Medium,
                        7.5,
                        "1. Confirm DefaultServlet's <init-param>readonly</init-param> is true (default).\n\
                         2. Restrict PUT/DELETE at the reverse proxy.\n\
                         3. Patch to Tomcat 7.0.81+, 8.5.23+, 9.0.1+ which block JSP PUTs by default.\n\
                         4. Apply <security-constraint> in web.xml restricting PUT/DELETE on /*.",
                    ));
                }
            }
            Err(_) => {}
        }

        // Test 4e: Default credentials advertised via WWW-Authenticate.
        // We never attempt login. We only flag when a 401 response on /manager/html
        // surfaces a Basic realm that is the Tomcat default ("Tomcat Manager
        // Application"). That value plus a Tomcat Server header is a known
        // misconfiguration finding without needing to send credentials.
        tests_run += 1;
        let manager_url_401 = format!("{}/manager/html", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&manager_url_401).await {
            if response.status_code == 401 {
                let wwwauth = response
                    .headers
                    .get("www-authenticate")
                    .or_else(|| response.headers.get("WWW-Authenticate"))
                    .cloned()
                    .unwrap_or_default();
                let wwwauth_lower = wwwauth.to_lowercase();
                if wwwauth_lower.contains("basic")
                    && (wwwauth_lower.contains("tomcat manager application")
                        || wwwauth_lower.contains("realm=\"tomcat\""))
                {
                    vulnerabilities.push(self.create_vulnerability(
                        &manager_url_401,
                        "TOMCAT_MANAGER_DEFAULT_REALM",
                        "Tomcat Manager Uses Default Basic Auth Realm",
                        &format!(
                            "Manager interface is publicly reachable and advertises the default realm string `{}` in its WWW-Authenticate header.\nThis is the install-time default and frequently ships with default credentials (tomcat/tomcat, admin/admin, role1/role1).",
                            wwwauth
                        ),
                        Severity::High,
                        Confidence::High,
                        7.5,
                        "1. Replace the default realm name and ensure tomcat-users.xml does not contain default accounts.\n\
                         2. Bind /manager and /host-manager to internal IPs only via RemoteAddrValve.\n\
                         3. Audit tomcat-users.xml for `tomcat`/`admin`/`role1` users.\n\
                         4. Rotate credentials and force a strong password policy.",
                    ));
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
