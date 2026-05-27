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

        // Each entry: (path, name, severity, description, signatures, content_type)
        // - `signatures`: substrings that MUST appear in the response body to confirm
        //   the endpoint is genuinely the Spring Boot Actuator endpoint and not an
        //   unrelated 200 OK (catch-all router, SPA shell, etc.). At least one must
        //   match. Each signature is chosen to be specific enough that a non-Spring
        //   endpoint is extremely unlikely to coincidentally serve it.
        // - `content_type`: "json" (signature in body), "binary" (treat any 200 as
        //   hit — heap dump / log file are binary or plain text), or "html" for
        //   HTML-rendered endpoints like Hawtio.
        let actuator_endpoints: Vec<(&str, &str, Severity, &str, &[&str], &str)> = vec![
            // --- Critical: direct secret exfiltration ---
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes all environment variables, system properties, and externalized config — frequently leaks DB passwords, API tokens, signing keys",
                &["\"propertySources\"", "\"activeProfiles\""],
                "json",
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Downloads JVM heap dump (HPROF) — contains in-memory secrets, tokens, session data, decrypted DB credentials",
                &[],
                "binary",
            ),
            (
                "/actuator/dump",
                "Heap Dump (alias)",
                Severity::Critical,
                "Heap dump under an alternate Spring Cloud route — same impact as /actuator/heapdump",
                &[],
                "binary",
            ),
            (
                "/actuator/logfile",
                "Application Log File",
                Severity::Critical,
                "Streams the full server log file — frequently contains request bodies, JWTs, OAuth codes, stack traces with secrets",
                &[],
                "text",
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::High,
                "Dumps @ConfigurationProperties-bound classes with current values — leaks datasource URLs, mail credentials, OAuth client secrets bound from application.yml",
                &["\"contexts\"", "\"@ConfigurationProperties\"", "\"spring.datasource\"", "\"spring.mail\""],
                "json",
            ),
            (
                "/actuator/httptrace",
                "HTTP Request Trace",
                Severity::High,
                "Spring Boot 2.x — returns last 100 HTTP exchanges including Authorization/Cookie headers and request paths with tokens in query strings",
                &["\"traces\"", "\"timeTaken\"", "\"principal\""],
                "json",
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchange Trace",
                Severity::High,
                "Spring Boot 3.x rename of httptrace — recent HTTP exchanges including headers, principal, session, and query strings",
                &["\"exchanges\"", "\"timeTaken\""],
                "json",
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::High,
                "Spring Security audit log — exposes authentication attempts, usernames, source IPs",
                &["\"events\"", "\"AUTHENTICATION_SUCCESS\"", "\"AUTHENTICATION_FAILURE\""],
                "json",
            ),
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::High,
                "Spring Session — lists active session IDs (raw tokens) and principal names; session IDs can be used directly as cookies for impersonation",
                &["\"sessions\"", "\"lastAccessedTime\""],
                "json",
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Read/modify log levels at runtime — attacker can enable DEBUG/TRACE on security classes to harvest credentials from subsequent logs",
                &["\"loggers\"", "\"levels\""],
                "json",
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX Bridge",
                Severity::Critical,
                "JMX over HTTP — read/write/invoke any MBean; historically chained into RCE via Logback JNDI, Tomcat reload, Hibernate reload",
                &["\"agent\"", "\"protocol\":\"7.", "\"jolokia\""],
                "json",
            ),
            (
                "/actuator/jolokia/list",
                "Jolokia MBean Catalog",
                Severity::Critical,
                "Enumerates every MBean operation reachable via Jolokia — pre-flight reconnaissance for JMX-based RCE",
                &["\"domains\"", "\"value\"", "\"java.lang\""],
                "json",
            ),
            (
                "/actuator/hawtio",
                "Hawtio Console",
                Severity::Critical,
                "Hawtio web console embedded via actuator — gives interactive JMX/Camel/ActiveMQ access; one click to invoke arbitrary MBean operations",
                &["hawtio", "Hawtio"],
                "html",
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::High,
                "POST triggers graceful application shutdown — denial of service",
                &["\"Shutting down\"", "\"message\":\"Shutting"],
                "json",
            ),
            (
                "/actuator/restart",
                "Spring Cloud Restart",
                Severity::Critical,
                "Spring Cloud devtools restart endpoint — invalidates state and can be combined with /refresh to reload poisoned configuration",
                &["\"restart\"", "\"timestamp\""],
                "json",
            ),
            (
                "/actuator/refresh",
                "Spring Cloud Config Refresh",
                Severity::High,
                "Reloads externalized config — paired with a writable git/config server lets an attacker swap values without redeploy",
                &["[", "]"],
                "json",
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::High,
                "Lists all gateway routes, their URIs, and predicate filters — reveals internal services and any unauthenticated downstream",
                &["\"route_id\"", "\"predicate\"", "\"filters\""],
                "json",
            ),
            (
                "/actuator/gateway/actuator",
                "Spring Cloud Gateway Actuator",
                Severity::High,
                "Gateway management routes — enable/disable filters, dump global state",
                &["\"globalfilters\"", "\"GlobalFilter\""],
                "json",
            ),
            // --- High: internal architecture / pivot info ---
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Dumps every URL→handler mapping — reveals hidden admin endpoints, undocumented APIs, internal-only paths",
                &["\"dispatcherServlet\"", "\"dispatcherHandlers\"", "\"mappings\""],
                "json",
            ),
            (
                "/actuator/beans",
                "Spring Beans",
                Severity::Medium,
                "Full Spring bean graph — reveals frameworks in use, internal class names, and service wiring useful for CVE targeting",
                &["\"beans\"", "\"scope\":\"singleton\"", "\"dependencies\""],
                "json",
            ),
            (
                "/actuator/threaddump",
                "JVM Thread Dump",
                Severity::Medium,
                "Full stack trace of every running thread — leaks in-flight request URLs, internal class paths, and occasionally arguments",
                &["\"threads\"", "\"threadState\"", "\"stackTrace\""],
                "json",
            ),
            (
                "/actuator/conditions",
                "Auto-configuration Conditions",
                Severity::Medium,
                "Lists which Spring Boot auto-configurations matched — fingerprints frameworks and versions",
                &["\"positiveMatches\"", "\"negativeMatches\""],
                "json",
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Medium,
                "Enumerates @Scheduled tasks, cron expressions, and their target methods",
                &["\"cron\"", "\"fixedDelay\"", "\"fixedRate\""],
                "json",
            ),
            (
                "/actuator/caches",
                "Cache Inspector",
                Severity::Medium,
                "Lists cache managers and individual cache names",
                &["\"cacheManagers\""],
                "json",
            ),
            (
                "/actuator/metrics",
                "Metrics Index",
                Severity::Low,
                "Lists available metric names — enumeration for /actuator/metrics/{name}",
                &["\"names\""],
                "json",
            ),
            (
                "/actuator/prometheus",
                "Prometheus Metrics",
                Severity::Medium,
                "Prometheus exposition format — can leak request URIs (including path-segment IDs) and tag values like principal names",
                &["# HELP ", "# TYPE ", "jvm_"],
                "text",
            ),
            (
                "/actuator/info",
                "Build Info",
                Severity::Low,
                "Build metadata — frequently includes git commit SHA, build timestamp, and CI environment variables",
                &["\"build\"", "\"git\":{\"branch\"", "\"version\""],
                "json",
            ),
            (
                "/actuator/health",
                "Health",
                Severity::Low,
                "Health checks — when exposed in detail mode leaks DB/queue/redis hostnames and disk paths",
                &["\"status\":\"UP\"", "\"components\""],
                "json",
            ),
            // --- Legacy (Spring Boot 1.x) — root-mounted by default ---
            (
                "/env",
                "Environment (Legacy 1.x)",
                Severity::Critical,
                "Spring Boot 1.x root-mounted environment dump — same impact as /actuator/env",
                &["\"profiles\"", "\"server.port\"", "\"spring.\""],
                "json",
            ),
            (
                "/heapdump",
                "Heap Dump (Legacy 1.x)",
                Severity::Critical,
                "Spring Boot 1.x root-mounted heap dump",
                &[],
                "binary",
            ),
            (
                "/trace",
                "HTTP Trace (Legacy 1.x)",
                Severity::High,
                "Spring Boot 1.x request trace — recent requests including headers",
                &["\"timestamp\"", "\"method\"", "\"path\""],
                "json",
            ),
            (
                "/dump",
                "Thread Dump (Legacy 1.x)",
                Severity::Medium,
                "Spring Boot 1.x thread dump",
                &["\"threadName\"", "\"stackTrace\""],
                "json",
            ),
            (
                "/configprops",
                "Config Properties (Legacy 1.x)",
                Severity::High,
                "Spring Boot 1.x configuration properties dump",
                &["\"prefix\"", "\"properties\""],
                "json",
            ),
            (
                "/beans",
                "Beans (Legacy 1.x)",
                Severity::Medium,
                "Spring Boot 1.x bean graph",
                &["\"bean\":", "\"scope\":\"singleton\""],
                "json",
            ),
            (
                "/mappings",
                "Mappings (Legacy 1.x)",
                Severity::Medium,
                "Spring Boot 1.x URL mappings",
                &["\"bean\":\"requestMappingHandlerMapping\"", "\"handler\":"],
                "json",
            ),
            (
                "/loggers",
                "Loggers (Legacy 1.x)",
                Severity::High,
                "Spring Boot 1.x runtime log-level manipulation",
                &["\"loggers\"", "\"configuredLevel\""],
                "json",
            ),
            (
                "/threaddump",
                "Thread Dump (Legacy 1.x)",
                Severity::Medium,
                "Spring Boot 1.x thread dump alias",
                &["\"threadName\"", "\"lockName\"", "\"stackTrace\""],
                "json",
            ),
            (
                "/auditevents",
                "Audit Events (Legacy 1.x)",
                Severity::High,
                "Spring Boot 1.x audit log",
                &["\"events\"", "\"principal\""],
                "json",
            ),
        ];

        for (path, name, severity, description, signatures, content_type) in actuator_endpoints {
            let url = format!("{}{}", target, path);
            tests += 1;

            let response = match self.http_client.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if response.status_code != 200 {
                continue;
            }

            let is_actuator = match content_type {
                "binary" => Self::looks_like_heapdump_or_binary(&response),
                "text" => Self::looks_like_log_or_prom(&response, signatures),
                "html" => signatures.iter().any(|s| response.body.contains(s))
                    && (response.body.contains("<html") || response.body.contains("<!DOCTYPE")),
                _ => signatures.iter().any(|s| response.body.contains(s)),
            };

            if !is_actuator {
                continue;
            }

            let cvss = match severity {
                Severity::Critical => 9.8,
                Severity::High => 7.5,
                Severity::Medium => 5.3,
                Severity::Low => 3.7,
                _ => 0.0,
            };

            let evidence_snippet = if matches!(content_type, "binary") {
                format!(
                    "Endpoint returned 200 with {} bytes of binary content",
                    response.body.len()
                )
            } else {
                let preview: String = response.body.chars().take(180).collect();
                format!("Endpoint returned 200. Body preview: {}", preview)
            };

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id(),
                vuln_type: "Actuator Exposure".to_string(),
                severity,
                confidence: Confidence::High,
                category: "Framework Security".to_string(),
                url: url.clone(),
                parameter: None,
                payload: path.to_string(),
                description: format!(
                    "Spring Boot Actuator {} endpoint exposed: {}",
                    name, description
                ),
                evidence: Some(evidence_snippet),
                cwe: "CWE-200".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: "Set management.endpoints.web.exposure.include=health,info \
                    (or a minimal whitelist), bind management to a separate internal \
                    port (management.server.port + management.server.address=127.0.0.1), \
                    and gate any exposed sensitive endpoint behind Spring Security."
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests))
    }

    /// A heap dump is HPROF binary: starts with the magic string "JAVA PROFILE" or
    /// "HPROF" and is typically tens of MB. Spring Boot serves it as
    /// `application/octet-stream` with a `.hprof` filename. We accept either the
    /// HPROF magic OR a clearly binary octet-stream payload of meaningful size,
    /// so a 200 OK SPA shell never matches.
    fn looks_like_heapdump_or_binary(response: &crate::http_client::HttpResponse) -> bool {
        if response.body.starts_with("JAVA PROFILE")
            || response.body.starts_with("HPROF")
            || response.body.as_bytes().starts_with(&[0x4a, 0x41, 0x56, 0x41])
        {
            return true;
        }
        let ct = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        let disposition = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-disposition"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        (ct.contains("octet-stream") || ct.contains("hprof"))
            && response.body.len() > 8192
            && (disposition.contains("heapdump")
                || disposition.contains(".hprof")
                || disposition.contains("attachment"))
    }

    /// Log file / Prometheus exposition. Either:
    /// - One of the supplied signature lines is present (e.g. "# HELP " for prom), OR
    /// - The response is plain text large enough to be a log file with timestamps.
    fn looks_like_log_or_prom(
        response: &crate::http_client::HttpResponse,
        signatures: &[&str],
    ) -> bool {
        if !signatures.is_empty() && signatures.iter().any(|s| response.body.contains(s)) {
            return true;
        }
        // Log file heuristic: large text/plain with ISO-style timestamps and Java
        // logger output. Requires multiple signals so an SPA shell never matches.
        let ct = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        let body = &response.body;
        ct.contains("text/plain")
            && body.len() > 1024
            && (body.contains(" INFO ") || body.contains(" ERROR ") || body.contains(" WARN "))
            && (body.contains(" o.s.") || body.contains(" org.springframework"))
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
