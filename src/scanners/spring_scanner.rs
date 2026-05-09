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

        // Each entry is (path, name, severity, description, signatures, is_binary).
        //
        // `signatures` is the set of strings — at least one must appear in the
        // response body to count as a hit. They are intentionally narrow JSON
        // field names that the matching actuator endpoint always emits; the
        // generic `{` plus `"status"` style was prone to matching any JSON API.
        //
        // `is_binary` is true for endpoints (heapdump, logfile, prometheus)
        // whose payload is not JSON, where we instead validate via Content-Type
        // and a per-endpoint sniff in the matching block below.
        let actuator_endpoints: &[(&str, &str, Severity, &str, &[&str], bool)] = &[
            // === Top-tier credential / secret leakage ===
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes all environment variables including secrets, datasource passwords, and API keys",
                &["\"propertySources\"", "\"activeProfiles\""],
                false,
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::Critical,
                "Exposes resolved @ConfigurationProperties values - includes datasource URLs, OAuth client secrets, and integration credentials",
                &["\"contexts\"", "\"configurationProperties\"", "\"beans\":{\"spring."],
                false,
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Allows downloading JVM heap dump - contains secrets, sessions, JWTs and in-memory credentials",
                &[],
                true,
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP - reachable MBeans can be invoked to read/write app state and frequently leads to RCE",
                &["\"agent\"", "\"jolokia\"", "\"MBeanServerDelegate\""],
                false,
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::Critical,
                "Can shutdown the application with a POST",
                &["\"message\":\"Shutting down","\"Method Not Allowed\""],
                false,
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::Critical,
                "Reveals all gateway routes including internal-only backends; combined with /actuator/refresh allows attacker-controlled routing",
                &["\"route_id\"", "\"predicates\"", "\"filters\":["],
                false,
            ),
            (
                "/actuator/refresh",
                "Spring Cloud Refresh",
                Severity::Critical,
                "POST endpoint that re-reads remote config; exploitable when paired with a poisoned config server to inject SpEL/SSTI payloads (CVE-2022-22963 / 22965 family)",
                &["\"Method Not Allowed\"", "\"Allow\":\"POST\""],
                false,
            ),
            // === Spring Cloud Config server – credential/secret oracle ===
            (
                "/encrypt/status",
                "Spring Cloud Config Encrypt Status",
                Severity::High,
                "Indicates Spring Cloud Config server with cipher endpoint exposed - /encrypt and /decrypt may leak the symmetric key",
                &["\"status\":\"OK\"", "NO_KEY", "INVALID_KEY"],
                false,
            ),
            // === High-impact stack / runtime introspection ===
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "Exposes JVM thread stacks - can leak request URLs with bearer tokens, internal hostnames and code paths",
                &["\"threads\"", "\"stackTrace\"", "\"lockedMonitors\""],
                false,
            ),
            (
                "/actuator/httptrace",
                "HTTP Trace",
                Severity::High,
                "Exposes recent HTTP requests including Authorization, Cookie and X-Api-Key headers",
                &["\"traces\"", "\"timeTaken\""],
                false,
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges (Boot 3.x)",
                Severity::High,
                "Exposes recent HTTP exchanges including request/response headers and bodies",
                &["\"exchanges\"", "\"timeTaken\"", "\"timestamp\""],
                false,
            ),
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::High,
                "Exposes active Spring Session entries; can include user IDs and session attributes",
                &["\"sessions\"", "\"lastAccessedTime\""],
                false,
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::High,
                "Exposes authentication audit log including usernames and login outcomes",
                &["\"events\"", "\"principal\""],
                false,
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Can modify log levels at runtime - enabling DEBUG/TRACE on auth packages frequently logs full credentials",
                &["\"loggers\"", "\"levels\""],
                false,
            ),
            (
                "/actuator/logfile",
                "Application Log File",
                Severity::High,
                "Streams the entire application log - typically contains stack traces with SQL, requests, and sometimes credentials",
                &[],
                true,
            ),
            (
                "/actuator/quartz",
                "Quartz Jobs",
                Severity::Medium,
                "Exposes Quartz job groups, schedules and trigger details",
                &["\"groups\":{", "\"jobs\":["],
                false,
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Medium,
                "Exposes @Scheduled task definitions including target class names and cron expressions",
                &["\"cron\":[", "\"fixedDelay\":[", "\"fixedRate\":["],
                false,
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changelog",
                Severity::Medium,
                "Exposes Liquibase migrations including SQL change descriptions",
                &["\"liquibaseBeans\"", "\"changeSets\""],
                false,
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Exposes Flyway migration history",
                &["\"flywayBeans\"", "\"migrations\":["],
                false,
            ),
            (
                "/actuator/beans",
                "Bean Definitions",
                Severity::Medium,
                "Reveals all Spring beans, their classes and dependency wiring - useful for gadget-chain discovery",
                &["\"beans\":{", "\"contexts\":{"],
                false,
            ),
            (
                "/actuator/conditions",
                "Autoconfig Conditions",
                Severity::Medium,
                "Reveals enabled/disabled autoconfigurations - exposes internal stack",
                &["\"positiveMatches\"", "\"negativeMatches\""],
                false,
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Exposes every controller mapping including hidden admin and internal-only routes",
                &["\"dispatcherServlet\"", "\"dispatcherHandlers\"", "\"mappings\":{"],
                false,
            ),
            (
                "/actuator/caches",
                "Caches",
                Severity::Low,
                "Lists configured cache managers and cache names",
                &["\"cacheManagers\""],
                false,
            ),
            (
                "/actuator/metrics",
                "Metrics Index",
                Severity::Low,
                "Lists Micrometer metric names; combined with /metrics/{name} can expose request URIs and tag values",
                &["\"names\":["],
                false,
            ),
            (
                "/actuator/prometheus",
                "Prometheus Metrics",
                Severity::Low,
                "Prometheus metrics scrape endpoint - URI tags can reveal admin/internal paths",
                &[],
                true,
            ),
            (
                "/actuator/info",
                "Application Info",
                Severity::Low,
                "App build/git info; sometimes contains commit hashes or branch names",
                &["\"git\":{", "\"build\":{\"version\""],
                false,
            ),
            (
                "/actuator/health",
                "Health",
                Severity::Low,
                "Health endpoint with details enabled exposes datasource URLs, queue names and downstream service URLs",
                &["\"status\":\"UP\"", "\"status\":\"DOWN\"", "\"components\":{"],
                false,
            ),
            (
                "/actuator/hystrix.stream",
                "Hystrix Stream",
                Severity::Medium,
                "Server-sent stream of circuit-breaker metrics - leaks downstream commands and group names",
                &[],
                true,
            ),
            (
                "/eureka/apps",
                "Eureka Service Registry",
                Severity::High,
                "Eureka server applications endpoint - lists every registered microservice with internal hostnames and IPs",
                &["<applications>", "\"applications\":{\"versions__delta\""],
                false,
            ),

            // === Spring Boot 1.x legacy endpoints (no /actuator prefix) ===
            (
                "/env",
                "Environment (Boot 1.x)",
                Severity::Critical,
                "Boot 1.x environment endpoint - exposes datasource and integration credentials",
                &["\"profiles\":[", "\"systemProperties\":{", "\"systemEnvironment\":{"],
                false,
            ),
            (
                "/heapdump",
                "Heap Dump (Boot 1.x)",
                Severity::Critical,
                "Boot 1.x heap dump endpoint",
                &[],
                true,
            ),
            (
                "/dump",
                "Thread Dump (Boot 1.x)",
                Severity::High,
                "Boot 1.x thread dump",
                &["\"threadName\"", "\"stackTrace\""],
                false,
            ),
            (
                "/trace",
                "HTTP Trace (Boot 1.x)",
                Severity::High,
                "Boot 1.x HTTP trace - leaks Authorization headers and cookies of recent requests",
                &["\"timestamp\"", "\"info\":{\"method\""],
                false,
            ),
            (
                "/configprops",
                "Configuration Properties (Boot 1.x)",
                Severity::Critical,
                "Boot 1.x configprops",
                &["\"prefix\"", "\"properties\":{"],
                false,
            ),
            (
                "/mappings",
                "URL Mappings (Boot 1.x)",
                Severity::Medium,
                "Boot 1.x mappings",
                &["\"bean\":\"requestMappingHandlerMapping\""],
                false,
            ),
            (
                "/beans",
                "Bean Definitions (Boot 1.x)",
                Severity::Medium,
                "Boot 1.x beans",
                &["\"bean\":\"", "\"resource\":\"class path resource"],
                false,
            ),
            (
                "/auditevents",
                "Audit Events (Boot 1.x)",
                Severity::High,
                "Boot 1.x audit events",
                &["\"events\":[", "\"principal\""],
                false,
            ),
            (
                "/loggers",
                "Loggers (Boot 1.x)",
                Severity::High,
                "Boot 1.x loggers",
                &["\"loggers\":{", "\"levels\":["],
                false,
            ),
            (
                "/logfile",
                "Log File (Boot 1.x)",
                Severity::High,
                "Boot 1.x logfile endpoint",
                &[],
                true,
            ),

            // === Common alternative management contexts ===
            (
                "/management/env",
                "Custom Management Env",
                Severity::Critical,
                "Custom management.endpoints.web.base-path environment endpoint",
                &["\"propertySources\""],
                false,
            ),
            (
                "/management/heapdump",
                "Custom Management Heapdump",
                Severity::Critical,
                "Custom management context heapdump",
                &[],
                true,
            ),
            (
                "/admin/env",
                "Admin-Prefixed Env",
                Severity::Critical,
                "/admin-prefixed actuator base-path env",
                &["\"propertySources\""],
                false,
            ),
            (
                "/admin/heapdump",
                "Admin-Prefixed Heapdump",
                Severity::Critical,
                "/admin-prefixed actuator base-path heapdump",
                &[],
                true,
            ),
        ];

        for (path, name, severity, description, signatures, is_binary) in actuator_endpoints {
            let url = format!("{}{}", target, path);
            tests += 1;

            let response = match self.http_client.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // /shutdown and /refresh return 405 Method Not Allowed on GET when
            // they are exposed - that itself confirms the endpoint exists.
            // /jolokia returns 200 even on bare GET. Other endpoints must 200.
            let is_method_signal = matches!(*path,
                "/actuator/shutdown" | "/actuator/refresh"
            ) && response.status_code == 405;

            if response.status_code != 200 && !is_method_signal {
                continue;
            }

            // Validate the body matches an endpoint-specific signature so we
            // don't false-positive on generic JSON APIs or SPA shells.
            let validated = if *is_binary {
                self.validate_binary_actuator(path, &response)
            } else if is_method_signal {
                // For 405 responses, require Allow header to confirm Spring Boot
                response
                    .headers
                    .get("allow")
                    .map(|h| h.to_uppercase().contains("POST"))
                    .unwrap_or(false)
                    || signatures.iter().any(|s| response.body.contains(s))
            } else if signatures.is_empty() {
                false
            } else {
                signatures.iter().any(|s| response.body.contains(s))
            };

            if !validated {
                continue;
            }

            let cvss = match severity {
                Severity::Critical => 9.8,
                Severity::High => 7.5,
                Severity::Medium => 5.3,
                Severity::Low => 3.7,
                _ => 3.0,
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
                description: format!("Spring Boot Actuator {} endpoint exposed: {}", name, description),
                evidence: Some(format!("Endpoint accessible: {}", path)),
                cwe: "CWE-200".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: "Secure actuator endpoints with authentication or disable in production (set management.endpoints.web.exposure.include=health,info)".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests))
    }

    /// Validate non-JSON actuator endpoints by content sniff + Content-Type.
    fn validate_binary_actuator(&self, path: &str, response: &crate::http_client::HttpResponse) -> bool {
        let ctype = response
            .headers
            .get("content-type")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        if path.contains("heapdump") {
            // .hprof files start with the magic "JAVA PROFILE 1.0.x".
            // Some servers gzip them or wrap with a download Content-Type.
            let is_octet = ctype.contains("application/octet-stream")
                || ctype.contains("application/x-gzip")
                || ctype.contains("application/vnd.spring-boot.actuator");
            let body_starts_with_hprof = response
                .body
                .as_bytes()
                .windows(12)
                .next()
                .map(|w| w.starts_with(b"JAVA PROFILE"))
                .unwrap_or(false);
            // Either a clear magic match, or a large octet-stream from this path.
            is_octet && (body_starts_with_hprof || response.body.len() > 50_000)
        } else if path.contains("prometheus") {
            // Prometheus exposition format always has these comment lines.
            response.body.contains("# HELP ") && response.body.contains("# TYPE ")
        } else if path.contains("logfile") {
            // Plain-text log content with typical timestamp / level patterns.
            ctype.contains("text/plain")
                && (response.body.contains(" INFO ")
                    || response.body.contains(" ERROR ")
                    || response.body.contains(" WARN ")
                    || response.body.contains("o.s.b."))
        } else if path.contains("hystrix.stream") {
            // SSE stream
            ctype.contains("text/event-stream")
                || response.body.contains("data: {\"type\":\"HystrixCommand\"")
                || response.body.contains("ping: ")
        } else {
            false
        }
    }

    async fn check_h2_console(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let h2_paths = vec![
            "/h2-console",
            "/h2-console/",
            "/h2-console/login.jsp",
            "/h2",
            "/h2/",
            "/console",
            "/console/",
            "/db",
            "/db/",
            "/admin/h2-console",
            "/dev/h2-console",
        ];

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
            "/swagger-ui/index.html",
            "/swagger-resources",
            "/swagger-resources/configuration/ui",
            "/swagger-resources/configuration/security",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/swagger-config",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api-docs/swagger-config",
            "/api/swagger-ui.html",
            "/api/v3/api-docs",
            "/webjars/swagger-ui/index.html",
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

        // Static-served Spring config files. Each must be matched against a
        // strict signature, otherwise a default 200-OK SPA response would
        // false-positive on the bare word "password" anywhere on the page.
        let config_paths = vec![
            "/application.properties",
            "/application.yml",
            "/application.yaml",
            "/application-dev.properties",
            "/application-dev.yml",
            "/application-prod.properties",
            "/application-prod.yml",
            "/application-staging.properties",
            "/application-test.properties",
            "/application-local.properties",
            "/bootstrap.properties",
            "/bootstrap.yml",
            "/bootstrap.yaml",
            "/WEB-INF/classes/application.properties",
            "/WEB-INF/classes/application.yml",
            "/WEB-INF/classes/bootstrap.properties",
            "/BOOT-INF/classes/application.properties",
            "/BOOT-INF/classes/application.yml",
            "/config/application.properties",
            "/config/application.yml",
        ];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    // Require a Spring-specific property prefix - the body must
                    // look like a real properties/YAML file, not an HTML page
                    // that happens to mention "password". Each pattern is
                    // unambiguous to Spring Boot configuration.
                    let body_lower = response.body.to_lowercase();
                    let looks_like_config = body_lower.contains("spring.datasource.url=")
                        || body_lower.contains("spring.datasource.url:")
                        || body_lower.contains("spring.datasource.password")
                        || body_lower.contains("spring.redis.")
                        || body_lower.contains("spring.kafka.")
                        || body_lower.contains("spring.rabbitmq.")
                        || body_lower.contains("spring.mail.password")
                        || body_lower.contains("spring.security.user.password")
                        || body_lower.contains("spring.cloud.config.")
                        || body_lower.contains("server.port=")
                        || body_lower.contains("server.port:")
                        || body_lower.contains("management.endpoints.")
                        || body_lower.contains("eureka.client.")
                        || body_lower.contains("spring.profiles.active");
                    if !looks_like_config {
                        continue;
                    }
                    let sensitive_patterns = vec![
                        "spring.datasource.password",
                        "spring.datasource.url=jdbc:",
                        "spring.datasource.url: jdbc:",
                        "jdbc:mysql://",
                        "jdbc:postgresql://",
                        "jdbc:oracle:",
                        "jdbc:sqlserver://",
                        "spring.security.user.password",
                        "spring.mail.password",
                        "spring.redis.password",
                        "spring.rabbitmq.password",
                        "spring.cloud.config.server.git.password",
                        "spring.cloud.aws.credentials.secret-key",
                        "aws.secret-key",
                        "azure.client-secret",
                        "encrypt.key=",
                        "encrypt.keyStore.password",
                    ];
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
