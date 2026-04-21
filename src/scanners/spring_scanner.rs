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

        // Actuator endpoints worth probing. Ordering roughly matches blast radius:
        // anything that exposes secrets, memory contents, or admin controls first.
        //
        // Paths are doubled up with:
        //   * `/actuator/<x>`        Spring Boot 2.x / 3.x default
        //   * `/<x>`                 Spring Boot 1.x legacy (still seen in enterprise)
        //   * `/manage/<x>`          common custom `management.endpoints.web.base-path`
        //   * `/admin/<x>`           common custom base path in Spring Cloud admin server
        let actuator_endpoints = vec![
            // === Critical — direct credential / memory / execution exposure ===
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes all environment variables including secrets",
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Allows downloading JVM heap dump - contains secrets, sessions, credentials",
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP - can invoke MBeans and lead to RCE",
            ),
            (
                "/actuator/jolokia/list",
                "Jolokia MBean List",
                Severity::Critical,
                "Enumerates JMX MBeans - precursor to Jolokia RCE",
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::Critical,
                "Can shutdown the application",
            ),
            (
                "/actuator/restart",
                "Application Restart",
                Severity::Critical,
                "Spring Cloud Context can restart the application context",
            ),
            (
                "/actuator/refresh",
                "Config Refresh",
                Severity::High,
                "Spring Cloud Config refresh - can force reload of remote config",
            ),
            (
                "/actuator/env.json",
                "Environment Variables (legacy .json)",
                Severity::Critical,
                "Legacy .json suffix environment endpoint",
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::High,
                "Exposes all @ConfigurationProperties - often contains DB URLs, secrets, tokens",
            ),
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "JVM thread dump - leaks method arguments, stack traces, internal state",
            ),
            (
                "/actuator/logfile",
                "Logfile Download",
                Severity::High,
                "Full application log - can contain secrets, tokens, PII",
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::High,
                "Authentication/authorization audit trail including usernames",
            ),
            (
                "/actuator/httptrace",
                "HTTP Trace",
                Severity::High,
                "Last 100 HTTP requests incl. headers (cookies, Authorization)",
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges",
                Severity::High,
                "Spring Boot 3.x HTTP exchange buffer incl. headers",
            ),
            (
                "/actuator/sessions",
                "Sessions",
                Severity::High,
                "Spring Session store - enumerate/delete active sessions",
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::High,
                "Exposes all routes; with /refresh enables SpEL-based RCE (CVE-2022-22947)",
            ),
            (
                "/actuator/gateway/actuator/gateway/routes",
                "Spring Cloud Gateway Routes (nested)",
                Severity::High,
                "Alternate gateway route dump path",
            ),
            (
                "/actuator/hystrix.stream",
                "Hystrix Event Stream",
                Severity::Medium,
                "Streams circuit-breaker metrics - can leak request URIs",
            ),
            (
                "/actuator/sbom",
                "Software Bill of Materials",
                Severity::Medium,
                "Full dependency inventory - feeds targeted CVE attacks",
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changesets",
                Severity::Medium,
                "Schema migration history - reveals DB structure",
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Schema migration history - reveals DB structure",
            ),
            (
                "/actuator/quartz",
                "Quartz Scheduler",
                Severity::Medium,
                "Exposes scheduled jobs - can reveal internal tasks",
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Medium,
                "Lists @Scheduled methods - reveals internal cron-like jobs",
            ),
            (
                "/actuator/beans",
                "Spring Beans",
                Severity::Medium,
                "Full bean graph - aids targeted exploitation",
            ),
            (
                "/actuator/conditions",
                "Auto-configuration Conditions",
                Severity::Medium,
                "Reveals which starters/configs are active",
            ),
            (
                "/actuator/caches",
                "Cache Manager",
                Severity::Medium,
                "Lists and evicts caches - can cause DoS or pollute caches",
            ),
            (
                "/actuator/integrationgraph",
                "Spring Integration Graph",
                Severity::Medium,
                "Messaging flow graph - reveals internal integration channels",
            ),
            (
                "/actuator/startup",
                "Application Startup Trace",
                Severity::Medium,
                "Full startup timing graph - reveals internal structure",
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Exposes all URL mappings (incl. undocumented admin routes)",
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Can modify log levels at runtime (e.g. enable DEBUG on security filters)",
            ),
            (
                "/actuator/metrics",
                "Metrics",
                Severity::Low,
                "Exposes operational metrics",
            ),
            (
                "/actuator/prometheus",
                "Prometheus Metrics",
                Severity::Low,
                "Prometheus-formatted metrics - can leak URIs, user IDs as label values",
            ),
            (
                "/actuator/info",
                "Application Info",
                Severity::Low,
                "Build/Git info - confirms version for CVE targeting",
            ),
            (
                "/actuator/health",
                "Health",
                Severity::Low,
                "Exposes health status",
            ),
            (
                "/actuator/health/readiness",
                "Health Readiness Probe",
                Severity::Low,
                "Kubernetes readiness probe",
            ),
            (
                "/actuator/health/liveness",
                "Health Liveness Probe",
                Severity::Low,
                "Kubernetes liveness probe",
            ),
            // === Legacy / Spring Boot 1.x ===
            (
                "/env",
                "Environment (Legacy)",
                Severity::Critical,
                "Legacy 1.x environment endpoint",
            ),
            (
                "/heapdump",
                "Heap Dump (Legacy)",
                Severity::Critical,
                "Legacy 1.x heap dump endpoint",
            ),
            (
                "/dump",
                "Thread Dump (Legacy)",
                Severity::High,
                "Legacy 1.x thread dump endpoint",
            ),
            (
                "/trace",
                "HTTP Trace (Legacy)",
                Severity::High,
                "Legacy 1.x HTTP trace - last N requests with full headers",
            ),
            (
                "/configprops",
                "Configuration Properties (Legacy)",
                Severity::High,
                "Legacy 1.x @ConfigurationProperties dump",
            ),
            (
                "/loggers",
                "Loggers (Legacy)",
                Severity::High,
                "Legacy 1.x runtime log-level control",
            ),
            (
                "/mappings",
                "URL Mappings (Legacy)",
                Severity::Medium,
                "Legacy 1.x URL mapping dump",
            ),
            (
                "/beans",
                "Beans (Legacy)",
                Severity::Medium,
                "Legacy 1.x bean graph dump",
            ),
            (
                "/autoconfig",
                "Auto-config Report (Legacy)",
                Severity::Medium,
                "Legacy 1.x auto-configuration report",
            ),
            (
                "/metrics",
                "Metrics (Legacy)",
                Severity::Low,
                "Legacy 1.x metrics endpoint",
            ),
            // === Common alternate management base paths (`/manage` and `/admin`) ===
            (
                "/manage/env",
                "Environment (custom base)",
                Severity::Critical,
                "Environment under custom management base-path",
            ),
            (
                "/manage/heapdump",
                "Heap Dump (custom base)",
                Severity::Critical,
                "Heap dump under custom management base-path",
            ),
            (
                "/manage/configprops",
                "ConfigProps (custom base)",
                Severity::High,
                "Configuration properties under custom management base-path",
            ),
            (
                "/manage/health",
                "Health (custom base)",
                Severity::Low,
                "Health under custom management base-path",
            ),
            (
                "/admin/env",
                "Environment (admin base)",
                Severity::Critical,
                "Environment under /admin base-path",
            ),
            (
                "/admin/heapdump",
                "Heap Dump (admin base)",
                Severity::Critical,
                "Heap dump under /admin base-path",
            ),
        ];

        for (path, name, severity, description) in actuator_endpoints {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    // Require actual actuator-specific content, not just any JSON.
                    // Previously matched `contains("{")` or `len() > 10` which
                    // matches ANY response and creates massive false positives.
                    //
                    // Path-specific structural anchors keep this at zero FP:
                    //   * heapdump   — binary .hprof, size/Content-Type check
                    //   * logfile    — plain log lines (`INFO `, `WARN `, …)
                    //   * prometheus — `# HELP` / `# TYPE` exposition format
                    //   * hystrix    — server-sent events `ping:` / `data: {"type":"Hystrix…`
                    //   * gateway    — JSON array with `"route_id"`
                    //   * sbom       — JSON with `"bomFormat"` or `"SPDX"`
                    //   * everything else — JSON with an actuator-unique key
                    let body = &response.body;
                    let is_actuator = if path.contains("heapdump") {
                        // HPROF magic header `JAVA PROFILE 1.0.`  is emitted as the
                        // first bytes of a real heap dump; accept on either the
                        // magic header, a .hprof content-type, or a very large body.
                        body.starts_with("JAVA PROFILE")
                            || response
                                .headers
                                .iter()
                                .any(|(k, v)| {
                                    k.eq_ignore_ascii_case("content-type")
                                        && (v.contains("hprof")
                                            || v.contains("octet-stream"))
                                })
                            || body.len() > 1_000_000
                    } else if path.ends_with("/logfile") {
                        // Spring's logfile endpoint streams the raw log; require
                        // at least two distinct log-level tokens to avoid matching
                        // prose.
                        let tokens =
                            ["INFO ", "WARN ", "ERROR ", "DEBUG ", "TRACE "];
                        tokens.iter().filter(|t| body.contains(*t)).count() >= 2
                    } else if path.ends_with("/prometheus") {
                        body.contains("# HELP ") && body.contains("# TYPE ")
                    } else if path.contains("hystrix.stream") {
                        body.contains("data: {\"type\":\"Hystrix")
                            || body.starts_with("ping:")
                    } else if path.contains("gateway/routes") {
                        body.contains("\"route_id\"") || body.contains("\"routeId\"")
                    } else if path.ends_with("/sbom") {
                        body.contains("\"bomFormat\"")
                            || body.contains("SPDX")
                            || body.contains("\"CycloneDX\"")
                    } else {
                        body.contains("{")
                            && (body.contains("\"status\"")
                                || body.contains("\"_links\"")
                                || body.contains("\"loggers\"")
                                || body.contains("\"levels\"")
                                || body.contains("\"propertySources\"")
                                || body.contains("\"activeProfiles\"")
                                || body.contains("\"dispatcherServlet\"")
                                || body.contains("\"contexts\"")
                                || body.contains("\"auditEvents\"")
                                || body.contains("\"traces\"")
                                || body.contains("\"exchanges\"")
                                || body.contains("\"threads\"")
                                || body.contains("\"threadName\"")
                                || body.contains("\"mappings\"")
                                || body.contains("\"beans\"")
                                || body.contains("\"caches\"")
                                || body.contains("\"cacheManagers\"")
                                || body.contains("\"scheduledTasks\"")
                                || body.contains("\"changeSets\"")
                                || body.contains("\"migrations\"")
                                || body.contains("\"quartzScheduler\"")
                                || body.contains("\"conditions\""))
                    };

                    if is_actuator {
                        let cvss = match severity {
                            Severity::Critical => 9.8,
                            Severity::High => 7.5,
                            Severity::Medium => 5.3,
                            _ => 3.7,
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
                            description: format!("Spring Boot Actuator {} endpoint exposed: {}", name, description),
                            evidence: Some(format!("Endpoint accessible: {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss,
                            verified: true,
                            false_positive: false,
                            remediation: "Secure actuator endpoints with authentication or disable in production".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
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
