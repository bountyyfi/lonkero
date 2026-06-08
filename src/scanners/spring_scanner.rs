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

        let (cloud_cfg_vulns, t) = self.check_spring_cloud_config(target).await?;
        vulnerabilities.extend(cloud_cfg_vulns);
        tests += t;

        let (gateway_vulns, t) = self.check_spring_cloud_gateway(target).await?;
        vulnerabilities.extend(gateway_vulns);
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
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "Exposes JVM thread state, call stacks, and may leak request data / credentials",
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
                "/actuator/beans",
                "Spring Beans",
                Severity::Medium,
                "Lists all Spring beans, packages, and DI graph - aids targeted exploitation",
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::High,
                "Exposes resolved @ConfigurationProperties - may include credentials",
            ),
            (
                "/actuator/conditions",
                "Auto-config Conditions",
                Severity::Low,
                "Exposes auto-configuration decisions and active classes",
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::Medium,
                "Exposes audit log including auth success/failure events",
            ),
            (
                "/actuator/httptrace",
                "HTTP Request Trace",
                Severity::High,
                "Exposes last 100 HTTP requests including Authorization headers / cookies",
            ),
            (
                "/actuator/trace",
                "HTTP Request Trace (Legacy)",
                Severity::High,
                "Legacy HTTP trace endpoint - leaks Authorization / Cookie headers",
            ),
            (
                "/actuator/sessions",
                "Session Inventory",
                Severity::High,
                "Lists / deletes active HTTP sessions",
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Low,
                "Exposes internal scheduled job definitions",
            ),
            (
                "/actuator/threads",
                "Live Threads",
                Severity::Medium,
                "Reactor / netty thread dump",
            ),
            (
                "/actuator/info",
                "Build/Git Info",
                Severity::Low,
                "Exposes build/git metadata which aids version-specific CVE targeting",
            ),
            (
                "/actuator/metrics",
                "Metrics",
                Severity::Low,
                "Exposes internal metric names and counters",
            ),
            (
                "/actuator/caches",
                "Cache Inventory",
                Severity::Low,
                "Lists internal cache names and can evict entries",
            ),
            (
                "/actuator/refresh",
                "Spring Cloud Refresh",
                Severity::High,
                "Allows runtime config refresh - chains with SnakeYAML deserialization in older versions",
            ),
            (
                "/actuator/restart",
                "Application Restart",
                Severity::Critical,
                "Restarts the application context",
            ),
            (
                "/actuator/pause",
                "Pause Application",
                Severity::High,
                "Pauses the application instance",
            ),
            (
                "/actuator/resume",
                "Resume Application",
                Severity::High,
                "Resumes a paused instance",
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::Critical,
                "Lists / mutates gateway routes (CVE-2022-22947 RCE surface when /actuator/gateway/refresh is writable)",
            ),
            (
                "/actuator/gateway/globalfilters",
                "Spring Cloud Gateway Filters",
                Severity::Medium,
                "Lists global gateway filters",
            ),
            (
                "/actuator/hystrix.stream",
                "Hystrix Event Stream",
                Severity::Medium,
                "Real-time circuit-breaker stream leaking request flow",
            ),
            (
                "/actuator/integrationgraph",
                "Spring Integration Graph",
                Severity::Low,
                "Exposes integration channels and components",
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changesets",
                Severity::Medium,
                "Exposes database migration history and schema names",
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Exposes database migration history",
            ),
            (
                "/actuator/quartz",
                "Quartz Scheduler",
                Severity::Low,
                "Exposes Quartz job and trigger definitions",
            ),
            (
                "/actuator/startup",
                "Startup Trace",
                Severity::Low,
                "Exposes Spring Boot startup steps and timing",
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
            (
                "/trace",
                "HTTP Trace (Legacy 1.x)",
                Severity::High,
                "Legacy 1.x HTTP trace endpoint",
            ),
            (
                "/dump",
                "Thread Dump (Legacy 1.x)",
                Severity::High,
                "Legacy 1.x thread dump",
            ),
            (
                "/configprops",
                "Config Props (Legacy)",
                Severity::High,
                "Legacy 1.x @ConfigurationProperties dump",
            ),
            (
                "/mappings",
                "URL Mappings (Legacy)",
                Severity::Medium,
                "Legacy 1.x URL mapping list",
            ),
            (
                "/beans",
                "Beans (Legacy)",
                Severity::Medium,
                "Legacy 1.x bean dump",
            ),
            (
                "/loggers",
                "Loggers (Legacy)",
                Severity::High,
                "Legacy 1.x logger control",
            ),
            (
                "/auditevents",
                "Audit Events (Legacy)",
                Severity::Medium,
                "Legacy 1.x audit log",
            ),
            (
                "/autoconfig",
                "Auto-config Report (Legacy)",
                Severity::Low,
                "Legacy 1.x auto-config report",
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
                    // Heap dump is a binary octet-stream; recognise by content-type or
                    // magic bytes rather than JSON shape so we don't false-positive on HTML.
                    let is_heapdump_body = if path.contains("heapdump") {
                        let ct = response
                            .headers
                            .get("content-type")
                            .or_else(|| response.headers.get("Content-Type"))
                            .map(|s| s.to_lowercase())
                            .unwrap_or_default();
                        let body_bytes = response.body.as_bytes();
                        let starts_with_hprof = body_bytes.starts_with(b"JAVA PROFILE");
                        let octet_stream = ct.contains("application/octet-stream")
                            || ct.contains("application/x-hprof")
                            || ct.contains("application/vnd.spring-boot.actuator");
                        // Large binary download with non-HTML CT is the heap dump
                        let big_binary = response.body.len() > 1024
                            && !ct.contains("text/html")
                            && !ct.contains("application/json");
                        starts_with_hprof || (octet_stream && big_binary)
                    } else {
                        false
                    };

                    // For JSON actuator responses, look for endpoint-shape markers.
                    // Each marker is specific enough that a generic SPA index.html will not match.
                    let body = &response.body;
                    let body_lower = body.to_lowercase();
                    let ct_lower = response
                        .headers
                        .get("content-type")
                        .or_else(|| response.headers.get("Content-Type"))
                        .map(|s| s.to_lowercase())
                        .unwrap_or_default();
                    let is_json_ct = ct_lower.contains("application/json")
                        || ct_lower.contains("application/vnd.spring-boot.actuator");

                    let json_shape = body.contains("{")
                        && is_json_ct
                        && (
                            body.contains("\"_links\"")
                            || body.contains("\"propertySources\"")
                            || body.contains("\"activeProfiles\"")
                            || body.contains("\"dispatcherServlet\"")
                            || body.contains("\"loggers\"")
                            || body.contains("\"levels\"")
                            || body.contains("\"threads\"")
                            || body.contains("\"threadName\"")
                            || body.contains("\"contexts\"")
                            || body.contains("\"beans\"")
                            || body.contains("\"configurationProperties\"")
                            || body.contains("\"conditions\"")
                            || body.contains("\"positiveMatches\"")
                            || body.contains("\"events\"")
                            || body.contains("\"traces\"")
                            || body.contains("\"sessions\"")
                            || body.contains("\"cachedTasks\"")
                            || body.contains("\"cron\"")
                            || body.contains("\"buildInfo\"")
                            || body.contains("\"git\"")
                            || body.contains("\"app\"")
                            || body.contains("\"measurements\"")
                            || body.contains("\"availableTags\"")
                            || body.contains("\"caches\"")
                            || body.contains("\"cacheManagers\"")
                            || body.contains("\"routes\"")
                            || body.contains("\"route_id\"")
                            || body.contains("\"globalFilters\"")
                            || body.contains("\"changeSets\"")
                            || body.contains("\"liquibaseBeans\"")
                            || body.contains("\"migrations\"")
                            || body.contains("\"timeline\"")
                            || body.contains("\"jobs\"")
                            || (body.contains("\"status\"")
                                && (body_lower.contains("\"up\"")
                                    || body_lower.contains("\"down\"")
                                    || body_lower.contains("\"out_of_service\"")))
                        );

                    let is_actuator = is_heapdump_body || json_shape;

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
            "/swagger-ui/index.html",
            "/swagger/index.html",
            "/swagger-resources",
            "/swagger-resources/configuration/ui",
            "/swagger-resources/configuration/security",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/swagger-config",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api/swagger.json",
            "/api/swagger-ui.html",
            "/api/v1/swagger.json",
            "/api/v2/api-docs",
            "/docs/api-docs",
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

        let config_paths = vec![
            "/env",
            "/application.properties",
            "/application.yml",
            "/application.yaml",
            "/application-dev.properties",
            "/application-dev.yml",
            "/application-prod.properties",
            "/application-prod.yml",
            "/application-staging.yml",
            "/application-test.yml",
            "/application-local.yml",
            "/bootstrap.properties",
            "/bootstrap.yml",
            "/bootstrap.yaml",
            "/config/application.properties",
            "/config/application.yml",
            "/config/bootstrap.yml",
            "/WEB-INF/application.properties",
            "/WEB-INF/application.yml",
            "/WEB-INF/classes/application.properties",
            "/WEB-INF/classes/application.yml",
            "/WEB-INF/classes/application-prod.yml",
            "/META-INF/maven/dependencies.txt",
        ];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    // Reject obvious HTML responses (SPA index, default error pages)
                    let ct = response
                        .headers
                        .get("content-type")
                        .or_else(|| response.headers.get("Content-Type"))
                        .map(|s| s.to_lowercase())
                        .unwrap_or_default();
                    let body_head = response.body.trim_start();
                    let looks_html = ct.contains("text/html")
                        || body_head.starts_with("<!DOCTYPE")
                        || body_head.starts_with("<!doctype")
                        || body_head.starts_with("<html");
                    if looks_html {
                        continue;
                    }

                    // Must look like a real properties/yaml/env-dump body before we
                    // flag credentials - prevents JSON SPA bundles tripping the check.
                    let looks_props = path.ends_with(".properties")
                        && response.body.contains('=')
                        && (response.body.contains("spring.")
                            || response.body.contains("server.port")
                            || response.body.contains("logging.")
                            || response.body.contains("management."));
                    let looks_yaml = (path.ends_with(".yml") || path.ends_with(".yaml"))
                        && response.body.contains(':')
                        && (response.body.contains("spring:")
                            || response.body.contains("server:")
                            || response.body.contains("management:")
                            || response.body.contains("logging:"));
                    let looks_env_dump = path == "/env"
                        && response.body.contains("\"propertySources\"");
                    if !(looks_props || looks_yaml || looks_env_dump) {
                        continue;
                    }

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

        let jolokia_paths = vec![
            "/jolokia",
            "/jolokia/",
            "/jolokia/list",
            "/jolokia/version",
            "/jolokia/read/java.lang:type=Runtime",
            "/actuator/jolokia",
            "/actuator/jolokia/list",
            "/api/jolokia",
            "/api/jolokia/version",
        ];

        for path in jolokia_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                // Jolokia responses are always JSON with a recognisable shape: an
                // "agent"/"protocol" version envelope or a "value" + "status":200 body.
                // Requiring the JSON shape, not just the word "jolokia", eliminates
                // marketing pages / search hits that happen to mention the word.
                let body = &response.body;
                let ct = response
                    .headers
                    .get("content-type")
                    .or_else(|| response.headers.get("Content-Type"))
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                let json_ct = ct.contains("application/json") || ct.contains("text/json");
                let jolokia_envelope = body.contains("\"agent\"")
                    && (body.contains("\"protocol\"") || body.contains("\"version\""));
                let jolokia_response = json_ct
                    && body.contains("\"timestamp\"")
                    && body.contains("\"status\"")
                    && body.contains("\"request\"");
                let mbean_listing = body.contains("\"MBeanServer\"")
                    || body.contains("MBeanServerDelegate")
                    || body.contains("java.lang:type=Runtime");
                if response.status_code == 200
                    && (jolokia_envelope || jolokia_response || mbean_listing)
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

    /// Spring Cloud Config Server exposes /{application}/{profile}[/{label}] and
    /// frequently leaks Vault / DB / SMTP credentials. When the server is unsecured,
    /// `/<anything>/default` returns a populated JSON envelope.
    async fn check_spring_cloud_config(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // /encrypt and /decrypt are Spring Cloud Config admin endpoints. They normally
        // return HTTP 400 with a specific Spring Boot error body when reachable
        // without arguments (proving the endpoint exists), and HTTP 200 when secrets
        // are pre-loaded for decrypt.
        let admin_paths: &[(&str, &str, Severity, &str)] = &[
            (
                "/encrypt/status",
                "Spring Cloud Config /encrypt/status",
                Severity::Medium,
                "Exposes whether config-server has an encryption key configured",
            ),
            (
                "/encrypt",
                "Spring Cloud Config /encrypt",
                Severity::High,
                "Symmetric encryption oracle - unauthenticated endpoint can encrypt arbitrary plaintext",
            ),
            (
                "/decrypt",
                "Spring Cloud Config /decrypt",
                Severity::Critical,
                "Symmetric decryption oracle - unauthenticated endpoint can decrypt cipher{...} values",
            ),
        ];
        for (path, name, severity, desc) in admin_paths {
            let url = format!("{}{}", target, path);
            tests += 1;
            // Most config-server installs expect POST; GET typically yields 405 / 400
            // with a "/encrypt" mention in the Spring Boot error body.
            if let Ok(resp) = self.http_client.get(&url).await {
                let body = &resp.body;
                let ct = resp
                    .headers
                    .get("content-type")
                    .or_else(|| resp.headers.get("Content-Type"))
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                let json_ct = ct.contains("application/json");
                // 405 with a Spring error envelope mentioning the path, OR a 200 with
                // JSON {"description":"...","status":"..."} envelope.
                let confirms = (resp.status_code == 405 || resp.status_code == 400)
                    && json_ct
                    && (body.contains("\"status\"") || body.contains("\"description\""))
                    && (body.contains(path) || body.to_lowercase().contains("method not allowed"));
                if confirms {
                    let cvss = match severity {
                        Severity::Critical => 9.8,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.7,
                    };
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Spring Cloud Config Admin Endpoint Exposed".to_string(),
                        severity: severity.clone(),
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!("{}: {}", name, desc),
                        evidence: Some(format!(
                            "Endpoint reachable (status {}) with Spring error envelope",
                            resp.status_code
                        )),
                        cwe: "CWE-284".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Place Spring Cloud Config Server behind authentication \
                             (spring.security.user.*) and bind /encrypt /decrypt to internal-only \
                             networks."
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
                }
            }
        }

        // Anonymous config retrieval. Use an unlikely application name so a normal
        // app's home page can't masquerade as a hit, and require the unique JSON
        // envelope keys that Spring Cloud Config Server returns.
        let probe_apps = [
            ("/__lonkero-probe/default", "default profile"),
            ("/__lonkero-probe/default/master", "master label"),
            ("/application/default", "shared application"),
            ("/myapp/default", "myapp default profile"),
        ];
        for (path, label) in probe_apps {
            let url = format!("{}{}", target, path);
            tests += 1;
            if let Ok(resp) = self.http_client.get(&url).await {
                if resp.status_code == 200 {
                    let body = &resp.body;
                    let ct = resp
                        .headers
                        .get("content-type")
                        .or_else(|| resp.headers.get("Content-Type"))
                        .map(|s| s.to_lowercase())
                        .unwrap_or_default();
                    if !ct.contains("application/json") {
                        continue;
                    }
                    // Spring Cloud Config envelope: {"name":"...","profiles":[...],
                    // "label":...,"version":...,"state":...,"propertySources":[...]}
                    let envelope = body.contains("\"propertySources\"")
                        && body.contains("\"profiles\"")
                        && body.contains("\"name\"");
                    if envelope {
                        // Severity hinges on whether the dump itself contains secrets.
                        let body_lower = body.to_lowercase();
                        let has_secrets = body_lower.contains("password")
                            || body_lower.contains("secret")
                            || body_lower.contains("api_key")
                            || body_lower.contains("apikey")
                            || body_lower.contains("token")
                            || body_lower.contains("jdbc:")
                            || body_lower.contains("vault.token")
                            || body_lower.contains("cipher{");
                        let severity = if has_secrets {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        let cvss = if has_secrets { 9.8 } else { 7.5 };
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Spring Cloud Config Server Unauthenticated".to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Spring Cloud Config Server returns application config without authentication ({}). {}",
                                label,
                                if has_secrets {
                                    "Response contains credentials / secrets."
                                } else {
                                    "Response is a populated propertySources envelope."
                                }
                            ),
                            evidence: Some(format!(
                                "JSON envelope with propertySources / profiles / name keys at {}",
                                path
                            )),
                            cwe: "CWE-306".to_string(),
                            cvss,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "Require authentication on Spring Cloud Config Server \
                                 (spring.security.user.*) and restrict network exposure to the \
                                 client services only."
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

    /// Spring Cloud Gateway specific surfaces. /actuator/gateway/routes leaks the
    /// internal routing table; the /actuator/gateway/refresh + filter chain combo
    /// is CVE-2022-22947 territory (SpEL-driven RCE) when writable.
    async fn check_spring_cloud_gateway(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let url = format!("{}/actuator/gateway/routes", target);
        tests += 1;
        if let Ok(resp) = self.http_client.get(&url).await {
            if resp.status_code == 200 {
                let body = &resp.body;
                let ct = resp
                    .headers
                    .get("content-type")
                    .or_else(|| resp.headers.get("Content-Type"))
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                // /actuator/gateway/routes returns a JSON array with route_id /
                // predicate / filters keys. Require all three to dodge generic JSON.
                let is_gateway = ct.contains("application/json")
                    && body.contains("\"route_id\"")
                    && body.contains("\"predicate\"")
                    && (body.contains("\"filters\"") || body.contains("\"uri\""));
                if is_gateway {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Spring Cloud Gateway Routes Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: "/actuator/gateway/routes".to_string(),
                        description:
                            "Spring Cloud Gateway route inventory is exposed. \
                             If POST /actuator/gateway/routes/{id} is also writable this is \
                             CVE-2022-22947 (SpEL RCE)."
                                .to_string(),
                        evidence: Some("Route entries with route_id / predicate / filters returned".to_string()),
                        cwe: "CWE-200".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Disable or authenticate the gateway actuator endpoints. Set \
                             management.endpoint.gateway.enabled=false and upgrade to \
                             spring-cloud-gateway 3.1.1+ (CVE-2022-22947)."
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
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
