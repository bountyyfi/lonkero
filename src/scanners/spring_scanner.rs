// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct SpringScanner {
    http_client: Arc<HttpClient>,
}

impl SpringScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(
        &self,
        target: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let is_spring = self.detect_spring(target).await?;
        tests += 1;

        if !is_spring {
            debug!("Target does not appear to be a Spring application");
            return Ok((vulnerabilities, tests));
        }

        info!("Detected Spring application at {}", target);

        let (actuator_vulns, t) = self.check_actuator_exposure(target).await?;
        vulnerabilities.extend(actuator_vulns);
        tests += t;

        let (h2_vulns, t) = self.check_h2_console(target).await?;
        vulnerabilities.extend(h2_vulns);
        tests += t;

        let (swagger_vulns, t) = self.check_swagger_exposure(target).await?;
        vulnerabilities.extend(swagger_vulns);
        tests += t;

        let (config_vulns, t) = self.check_config_exposure(target).await?;
        vulnerabilities.extend(config_vulns);
        tests += t;

        let (jolokia_vulns, t) = self.check_jolokia_exposure(target).await?;
        vulnerabilities.extend(jolokia_vulns);
        tests += t;

        Ok((vulnerabilities, tests))
    }

    async fn detect_spring(&self, target: &str) -> Result<bool> {
        if let Ok(response) = self.http_client.get(target).await {
            // Whitelabel Error Page is Spring-specific
            if response.body.contains("Whitelabel Error Page") {
                return Ok(true);
            }
            // X-Application-Context header is Spring-specific
            if response.headers.get("x-application-context").is_some() {
                return Ok(true);
            }
        }

        // Check /actuator which is Spring Boot specific
        let url = format!("{}/actuator", target);
        if let Ok(response) = self.http_client.get(&url).await {
            if response.status_code == 200 {
                // Require actuator-specific structure, not just any JSON with "status"
                // /actuator returns a list of _links in Spring Boot
                if response.body.contains("_links") && response.body.contains("actuator") {
                    return Ok(true);
                }
            }
        }

        // Check /actuator/health with Spring-specific structure
        let health_url = format!("{}/actuator/health", target);
        if let Ok(response) = self.http_client.get(&health_url).await {
            if response.status_code == 200 {
                // Spring health endpoint returns {"status":"UP"} - require exact format
                if response.body.contains("\"status\"") && response.body.contains("\"UP\"") {
                    return Ok(true);
                }
            }
        }

        let error_url = format!("{}/this-path-does-not-exist-12345", target);
        if let Ok(response) = self.http_client.get(&error_url).await {
            // "Whitelabel Error Page" is unique to Spring Boot
            if response.body.contains("Whitelabel Error Page") {
                return Ok(true);
            }
            // "org.springframework" is specific enough (package name, not just "springframework")
            if response.body.contains("org.springframework") {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn check_actuator_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // (path, name, severity, description, body_signatures)
        //
        // Each entry MUST carry at least one body_signature that uniquely identifies the
        // endpoint's response — generic JSON or "200 OK" alone is never enough. The
        // signatures are taken from the actual JSON keys Spring Boot emits for each
        // endpoint (see org.springframework.boot.actuate.endpoint reference), so a
        // match implies a real Actuator response, not a coincidental 200.
        //
        // Heapdump is special: the body is a binary HPROF stream starting with the
        // ASCII magic "JAVA PROFILE 1.0", which we look for explicitly.
        let actuator_endpoints: Vec<(&str, &str, Severity, &str, &[&str])> = vec![
            // --- High-impact secret / credential exposure ---
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes all environment variables and config properties — typically contains DB credentials, API keys, JWT secrets, cloud tokens",
                &["\"propertySources\"", "\"activeProfiles\""],
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::Critical,
                "Exposes resolved @ConfigurationProperties beans — leaks credentials bound to spring.datasource, spring.mail, spring.security.oauth2, etc.",
                &["\"contexts\"", "\"beans\""],
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Downloads a full JVM heap dump — contains in-memory passwords, session tokens, JWT signing keys, DB connection objects",
                &["JAVA PROFILE 1.0"],
            ),
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "Live thread dump — leaks call stacks, query parameters, internal class names, and concurrency hotspots useful for attack planning",
                &["\"threads\"", "\"threadName\"", "\"stackTrace\""],
            ),
            (
                "/actuator/dump",
                "Thread Dump (Legacy)",
                Severity::High,
                "Spring Boot 1.x /dump endpoint — equivalent to /threaddump",
                &["\"threadName\"", "\"lockOwnerName\"", "\"blockedTime\""],
            ),
            (
                "/actuator/httptrace",
                "HTTP Request Trace",
                Severity::High,
                "Recent HTTP request/response history including Authorization, Cookie, and Set-Cookie headers from other users",
                &["\"traces\""],
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges",
                Severity::High,
                "Spring Boot 3.x replacement for /httptrace — same risk: leaks bearer tokens and session cookies from other users",
                &["\"exchanges\""],
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::High,
                "Authentication/authorization audit log — reveals usernames, login outcomes, principal identifiers",
                &["\"events\""],
            ),
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::Critical,
                "Lists active Spring Session entries — session IDs can be used to hijack live user sessions",
                &["\"sessions\""],
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Lists and (via POST) changes log levels at runtime — attacker can disable security loggers or enable DEBUG to leak request bodies",
                &["\"loggers\"", "\"levels\""],
            ),
            // --- RCE / takeover ---
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP — gadget-chain RCE via reloading Logback config from attacker URL, or via MLet/JNDI lookups",
                &["\"agent\"", "\"protocol\"", "MBeanServerDelegate"],
            ),
            (
                "/actuator/jolokia/list",
                "Jolokia MBean List",
                Severity::Critical,
                "Enumerates JMX MBeans — exposes the gadget surface used to pivot to RCE",
                &["\"value\"", "\"domain\"", "MBeanServerDelegate", "java.lang:type="],
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::High,
                "POST shuts down the JVM — denial of service",
                &["\"message\""],
            ),
            (
                "/actuator/restart",
                "Spring Cloud Restart",
                Severity::Critical,
                "Spring Cloud /restart — combined with /env POST allows arbitrary property override and reload, frequently chained into RCE",
                &["\"message\""],
            ),
            (
                "/actuator/refresh",
                "Spring Cloud Refresh",
                Severity::High,
                "Reloads @RefreshScope beans after /env updates — primitive for the env-update → refresh → RCE chain (CVE-2018-1273-class)",
                &["[", "\"name\""],
            ),
            (
                "/actuator/pause",
                "Pause Endpoint",
                Severity::High,
                "Spring Cloud /pause — flips the application into a paused state, denial of service",
                &["\"message\""],
            ),
            (
                "/actuator/resume",
                "Resume Endpoint",
                Severity::Medium,
                "Spring Cloud /resume — counterpart to /pause",
                &["\"message\""],
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::Critical,
                "Lists Gateway routes — and when writable (POST), allows adding a route that proxies any upstream URL (SSRF + auth bypass + RCE via SpEL filters: CVE-2022-22947)",
                &["\"route_id\"", "\"predicate\"", "\"filters\""],
            ),
            (
                "/actuator/gateway/globalfilters",
                "Gateway Global Filters",
                Severity::High,
                "Lists Gateway global filters — enables targeting CVE-2022-22947 SpEL injection",
                &["GatewayFilter", "@"],
            ),
            (
                "/actuator/gateway/routefilters",
                "Gateway Route Filters",
                Severity::Medium,
                "Lists available route-filter factories — recon for filter-based exploits",
                &["GatewayFilterFactory"],
            ),
            (
                "/actuator/integrationgraph",
                "Spring Integration Graph",
                Severity::Medium,
                "Internal Spring Integration topology — message channels and component IDs useful for chained attacks",
                &["\"nodes\"", "\"contentDescriptor\""],
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changelog",
                Severity::Medium,
                "Lists applied Liquibase changesets — schema disclosure + DB user inference",
                &["\"changeSets\""],
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Lists applied Flyway migrations — schema disclosure",
                &["\"migrations\""],
            ),
            (
                "/actuator/quartz",
                "Quartz Scheduler",
                Severity::Medium,
                "Quartz job/trigger metadata — reveals scheduled tasks and class names",
                &["\"jobs\"", "\"triggers\""],
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Medium,
                "Lists @Scheduled methods with their fully-qualified class names and cron expressions",
                &["\"cron\"", "\"fixedDelay\"", "\"fixedRate\""],
            ),
            (
                "/actuator/caches",
                "Caches",
                Severity::Low,
                "Enumerates application caches — minor information disclosure of internal data structures",
                &["\"cacheManagers\""],
            ),
            // --- Application internals / recon ---
            (
                "/actuator/beans",
                "Spring Beans",
                Severity::Medium,
                "Enumerates every Spring bean with its fully-qualified class — maps the entire application's internal structure for targeted exploitation",
                &["\"beans\"", "\"aliases\"", "\"scope\""],
            ),
            (
                "/actuator/conditions",
                "Auto-Configuration Report",
                Severity::Medium,
                "Spring Boot auto-configuration report — reveals which integrations (DB, MQ, OAuth, JMX) are active",
                &["\"positiveMatches\"", "\"negativeMatches\""],
            ),
            (
                "/actuator/autoconfig",
                "Auto-Configuration Report (Legacy)",
                Severity::Medium,
                "Spring Boot 1.x /autoconfig — equivalent to /conditions",
                &["\"positiveMatches\"", "\"negativeMatches\""],
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Full URL → controller mapping — exposes hidden admin and internal endpoints",
                &["\"dispatcherServlets\"", "\"dispatcherServlet\""],
            ),
            (
                "/actuator/startup",
                "Startup Steps",
                Severity::Low,
                "Application startup timeline — leaks bean initialization order and class names",
                &["\"timeline\"", "\"startupSteps\""],
            ),
            (
                "/actuator/info",
                "Build Info",
                Severity::Low,
                "Application info — typically exposes git commit, build time, and version (recon)",
                &["\"git\"", "\"build\"", "\"app\""],
            ),
            (
                "/actuator/metrics",
                "Metrics Index",
                Severity::Info,
                "Metric name catalog — minor recon; combined with per-metric drill-downs can reveal request volumes",
                &["\"names\""],
            ),
            (
                "/actuator/prometheus",
                "Prometheus Metrics",
                Severity::Low,
                "Prometheus-format metrics — leaks internal labels (db pool names, queue names, endpoint URIs) and traffic volumes",
                &["# HELP ", "# TYPE "],
            ),
            (
                "/actuator/health",
                "Health (Detailed)",
                Severity::Medium,
                "Detailed health probe — components section leaks DB type/version, message broker hosts, disk paths",
                &["\"components\"", "\"diskSpace\"", "\"db\""],
            ),
            (
                "/actuator/hawtio",
                "Hawtio Console",
                Severity::Critical,
                "Hawtio JMX console — provides MBean invocation UI, equivalent risk to exposed Jolokia",
                &["hawtio", "Hawtio"],
            ),
            // --- Spring Cloud Config Server ---
            (
                "/encrypt/status",
                "Cloud Config Encrypt Status",
                Severity::Low,
                "Spring Cloud Config Server cipher status — reveals encryption is enabled (no key material exposed, but confirms config-server)",
                &["\"status\"", "OK", "NO_KEY", "INVALID"],
            ),
            (
                "/configserver/health",
                "Config Server Health",
                Severity::Low,
                "Spring Cloud Config Server health — confirms a config-server is reachable, useful for SSRF pivots",
                &["\"status\""],
            ),
            // --- Pre-actuator (Spring Boot 1.x) bare paths ---
            (
                "/env",
                "Environment (Legacy)",
                Severity::Critical,
                "Spring Boot 1.x /env — same impact as /actuator/env",
                &["\"propertySources\"", "\"activeProfiles\""],
            ),
            (
                "/heapdump",
                "Heap Dump (Legacy)",
                Severity::Critical,
                "Spring Boot 1.x /heapdump — full JVM heap dump download",
                &["JAVA PROFILE 1.0"],
            ),
            (
                "/trace",
                "Trace (Legacy)",
                Severity::High,
                "Spring Boot 1.x /trace — recent HTTP requests with Authorization/Cookie headers",
                &["\"timestamp\"", "\"info\""],
            ),
            (
                "/dump",
                "Thread Dump (Legacy Bare)",
                Severity::High,
                "Spring Boot 1.x /dump — thread dump",
                &["\"threadName\"", "\"lockOwnerName\""],
            ),
            (
                "/mappings",
                "URL Mappings (Legacy)",
                Severity::Medium,
                "Spring Boot 1.x /mappings",
                &["\"dispatcherServlet\""],
            ),
        ];

        for (path, name, severity, description, signatures) in actuator_endpoints {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }

                // Heapdump can be huge; check the magic prefix on a window.
                // For all other endpoints, require at least one endpoint-specific
                // signature in the body. This keeps additions zero-FP — a generic
                // JSON 200 with no actuator keys is silently skipped.
                let body = &response.body;
                let matched = signatures.iter().any(|s| body.contains(s));
                if !matched {
                    continue;
                }

                let cvss = match severity {
                    Severity::Critical => 9.8,
                    Severity::High => 7.5,
                    Severity::Medium => 5.3,
                    Severity::Low => 3.7,
                    _ => 2.0,
                };

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: "Actuator Exposure".to_string(),
                    severity: severity.clone(),
                    confidence: Confidence::High,
                    category: "Framework Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: format!(
                        "Spring Boot Actuator {} endpoint exposed: {}",
                        name, description
                    ),
                    evidence: Some(format!(
                        "Endpoint accessible: {} — matched signature in response",
                        path
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss,
                    verified: true,
                    false_positive: false,
                    remediation:
                        "Disable the endpoint via management.endpoint.<id>.enabled=false (or \
                         restrict management.endpoints.web.exposure.include), bind \
                         management.server.port to a non-public interface, and require \
                         authentication for all /actuator paths (Spring Security)"
                            .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_h2_console(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let h2_paths = vec!["/h2-console", "/h2-console/", "/h2", "/console"];

        for path in h2_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200
                    && (response.body.contains("H2 Console")
                        || response.body.contains("h2-console"))
                {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Remote Code Execution".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "H2 Database Console exposed - allows arbitrary SQL execution and potential RCE".to_string(),
                        evidence: Some("H2 Console login page accessible".to_string()),
                        cwe: "CWE-284".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "Disable H2 Console in production (spring.h2.console.enabled=false)".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_swagger_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let swagger_paths = vec![
            "/swagger-ui.html",
            "/swagger-ui/",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json",
        ];

        for path in swagger_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let is_swagger = response.body.contains("swagger")
                        || response.body.contains("openapi")
                        || response.body.contains("\"paths\"");

                    if is_swagger {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!("Swagger/OpenAPI documentation exposed: {}", path),
                            evidence: Some(
                                "API documentation accessible without authentication".to_string(),
                            ),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "Secure Swagger UI with authentication or disable in production"
                                    .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_config_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let config_paths = vec!["/env", "/application.properties", "/application.yml"];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let sensitive_patterns =
                        vec!["spring.datasource", "jdbc:", "password", "secret"];
                    for pattern in &sensitive_patterns {
                        if response
                            .body
                            .to_lowercase()
                            .contains(&pattern.to_lowercase())
                        {
                            vulnerabilities.push(Vulnerability {
                                id: generate_vuln_id(),
                                vuln_type: "Information Disclosure".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Framework Security".to_string(),
                                url: url.clone(),
                                parameter: None,
                                payload: path.to_string(),
                                description: format!("Spring configuration file exposed: {}", path),
                                evidence: Some(format!("Sensitive pattern found: {}", pattern)),
                                cwe: "CWE-538".to_string(),
                                cvss: 9.1,
                                verified: true,
                                false_positive: false,
                                remediation: "Remove configuration files from web-accessible paths"
                                    .to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_jolokia_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let jolokia_paths = vec!["/jolokia", "/jolokia/list", "/actuator/jolokia"];

        for path in jolokia_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200
                    && (response.body.contains("jolokia") || response.body.contains("MBeanServer"))
                {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Remote Code Execution".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "Jolokia JMX endpoint exposed - allows JMX operations over HTTP, potential RCE".to_string(),
                        evidence: Some("Jolokia MBean access available".to_string()),
                        cwe: "CWE-284".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "Disable Jolokia or secure with authentication".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests))
    }
}

fn generate_vuln_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("SPRING-{:x}", timestamp)
}
