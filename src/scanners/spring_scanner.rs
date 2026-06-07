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

        let actuator_endpoints = vec![
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
                "Allows downloading JVM heap dump - contains secrets",
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Exposes all URL mappings",
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Can modify log levels at runtime",
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP - can lead to RCE",
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::Critical,
                "Can shutdown the application",
            ),
            (
                "/actuator/health",
                "Health",
                Severity::Low,
                "Exposes health status",
            ),
            (
                "/env",
                "Environment (Legacy)",
                Severity::Critical,
                "Legacy environment endpoint",
            ),
            (
                "/heapdump",
                "Heap Dump (Legacy)",
                Severity::Critical,
                "Legacy heap dump endpoint",
            ),
            // /actuator/configprops dumps every @ConfigurationProperties bean - this is
            // where datasource URLs, message broker URIs, OAuth client secrets and
            // third-party API keys typically live. Same payoff as /env.
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::Critical,
                "Dumps @ConfigurationProperties beans - typically contains datasource URLs, broker URIs, OAuth secrets",
            ),
            // /actuator/beans lists every Spring bean and its dependencies - perfect
            // recon for chaining further exploitation (find DataSource beans, AuthN
            // providers, etc.).
            (
                "/actuator/beans",
                "Bean Definitions",
                Severity::Medium,
                "Lists every Spring bean and its dependencies - aids further exploitation",
            ),
            // Thread dumps contain stack traces with parameter values, headers, and
            // sometimes Authorization tokens of in-flight requests.
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "JVM thread stacks - may contain in-flight request parameters and tokens",
            ),
            (
                "/actuator/dump",
                "Thread Dump (Legacy)",
                Severity::High,
                "Spring Boot 1.x thread dump endpoint",
            ),
            // HTTP trace/exchanges record the last N HTTP requests *including*
            // Authorization, Cookie and Set-Cookie headers - direct session theft.
            (
                "/actuator/httptrace",
                "HTTP Trace",
                Severity::Critical,
                "Recent HTTP requests with Authorization/Cookie headers - session theft",
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges",
                Severity::Critical,
                "Spring Boot 3.x HTTP trace - recent requests with Authorization/Cookie headers",
            ),
            (
                "/trace",
                "HTTP Trace (Legacy)",
                Severity::Critical,
                "Spring Boot 1.x HTTP trace endpoint",
            ),
            // Audit events expose authentication failures/successes and the
            // principals involved.
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::High,
                "Authentication events including principal usernames and failure reasons",
            ),
            // Scheduled tasks reveal internal service hostnames and job semantics.
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Medium,
                "Reveals internal cron jobs, target hosts and intervals",
            ),
            (
                "/actuator/quartz",
                "Quartz Scheduler",
                Severity::Medium,
                "Quartz jobs/triggers - exposes internal job configuration",
            ),
            (
                "/actuator/integrationgraph",
                "Spring Integration Graph",
                Severity::Medium,
                "Reveals internal Spring Integration flow channels and adapters",
            ),
            // Sessions endpoint exposes session IDs - direct hijack vector.
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::Critical,
                "Lists active HTTP session IDs - direct session hijack",
            ),
            // /actuator/caches can leak cached payloads (including authenticated
            // user data) when combined with cache reading.
            (
                "/actuator/caches",
                "Cache Names",
                Severity::Low,
                "Names of internal caches - aids cache poisoning/disclosure attacks",
            ),
            (
                "/actuator/conditions",
                "Autoconfig Conditions",
                Severity::Low,
                "Reveals enabled/disabled auto-configurations - aids fingerprinting",
            ),
            // /actuator/info often contains git.commit.id, version, build host —
            // useful for matching public CVEs to the running build.
            (
                "/actuator/info",
                "Application Info",
                Severity::Low,
                "Build metadata (git SHA, version, host) - aids CVE matching",
            ),
            // Prometheus / metrics may contain hostnames and queue depths.
            (
                "/actuator/prometheus",
                "Prometheus Metrics",
                Severity::Low,
                "Internal metrics may reveal hostnames, queues, internal service names",
            ),
            (
                "/actuator/metrics",
                "Metrics",
                Severity::Low,
                "Internal metric names may reveal service topology",
            ),
            // Refresh/restart endpoints can be POSTed to trigger configuration
            // reload or context restart - same severity as /shutdown.
            (
                "/actuator/refresh",
                "Spring Cloud Refresh",
                Severity::Critical,
                "Spring Cloud configuration refresh - reloads remote config (denial-of-service / config injection)",
            ),
            (
                "/actuator/restart",
                "Spring Cloud Restart",
                Severity::Critical,
                "Spring Cloud context restart - denial-of-service",
            ),
            // CVE-2022-22947: Spring Cloud Gateway actuator allows arbitrary code
            // execution via SpEL when /actuator/gateway/routes is writable.
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::Critical,
                "Exposes gateway routes; if writable, CVE-2022-22947 allows SpEL RCE",
            ),
            (
                "/actuator/gateway/refresh",
                "Gateway Refresh",
                Severity::High,
                "Triggers reload of Spring Cloud Gateway routes",
            ),
            // Flyway/Liquibase reveal historical schema migrations including
            // sensitive table/column names.
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Database migration history including table and column names",
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changesets",
                Severity::Medium,
                "Database changeset history - reveals schema",
            ),
            // SBOM in Spring Boot 3.3+ exposes the dependency list verbatim,
            // making n-day exploitation trivial.
            (
                "/actuator/sbom/application",
                "Application SBOM",
                Severity::Medium,
                "Full software bill of materials - aids n-day exploitation",
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
                    // /actuator/prometheus is plain text (# HELP / # TYPE format), not
                    // JSON, so it needs its own check. Same for the heap dump (binary).
                    let body = &response.body;
                    let is_prometheus = path.ends_with("/prometheus")
                        && body.contains("# HELP")
                        && body.contains("# TYPE");
                    let is_actuator = path.contains("heapdump")
                        || is_prometheus
                        || (body.contains("{") && (
                            body.contains("\"status\"")
                            || body.contains("\"_links\"")
                            || body.contains("\"loggers\"")
                            || body.contains("\"levels\"")
                            || body.contains("\"propertySources\"")
                            || body.contains("\"activeProfiles\"")
                            || body.contains("\"dispatcherServlet\"")
                            // Spring Boot 2.x+ wraps most endpoint payloads in
                            // `{"contexts":{"application":{...}}}`. The literal
                            // `"contexts"` key plus a `{` is a strong Spring marker.
                            || (body.contains("\"contexts\"") && body.contains("\"application\""))
                            // /actuator/threaddump
                            || (body.contains("\"threads\"") && body.contains("\"threadName\""))
                            // /actuator/httptrace and /actuator/httpexchanges
                            || (body.contains("\"traces\"") && body.contains("\"timeTaken\""))
                            || (body.contains("\"exchanges\"") && body.contains("\"timeTaken\""))
                            // /actuator/auditevents
                            || (body.contains("\"events\"") && body.contains("\"principal\"") && body.contains("\"timestamp\""))
                            // /actuator/scheduledtasks
                            || (body.contains("\"cron\"") && body.contains("\"runnable\""))
                            // /actuator/sessions (Spring Session)
                            || (body.contains("\"sessions\"") && body.contains("\"creationTime\""))
                            // /actuator/caches
                            || (body.contains("\"cacheManagers\"") && body.contains("\"caches\""))
                            // /actuator/metrics
                            || (body.contains("\"names\"") && (body.contains("\"jvm.") || body.contains("\"http.server.requests\"")))
                            // /actuator/info — Spring git/build/java sections
                            || (body.contains("\"git\"") && body.contains("\"commit\""))
                            // Spring Cloud Gateway /actuator/gateway/routes
                            || (body.contains("\"route_id\"") && body.contains("\"predicates\""))
                            // /actuator/integrationgraph
                            || (body.contains("\"contentDescriptor\"") && body.contains("\"nodes\""))
                            // /actuator/sbom/application
                            || (body.contains("\"bomFormat\"") && body.contains("CycloneDX"))
                        ));

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
