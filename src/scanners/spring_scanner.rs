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

        // Each entry pairs a path with the response-body anchor(s) that uniquely
        // identify a real Spring Actuator response. Anchors are JSON keys that
        // Actuator emits but are not common in arbitrary JSON APIs, eliminating
        // false positives even when a target returns 200 to every path.
        // Heap dumps are binary so they get a separate magic-byte check below.
        type ActuatorAnchor = &'static [&'static str];
        let actuator_endpoints: &[(&str, &str, Severity, &str, ActuatorAnchor)] = &[
            // --- Boot 2.x/3.x /actuator/* (most modern apps) ---
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes all environment variables and config property sources, often including database passwords and API keys",
                &["\"propertySources\"", "\"activeProfiles\""],
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::Critical,
                "Exposes all @ConfigurationProperties values, including spring.datasource.password and similar secrets",
                &["\"contexts\"", "\"prefix\":", "\"properties\":"],
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Allows downloading JVM heap dump - contains in-memory secrets, tokens, and session data",
                &[], // binary - handled separately
            ),
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "Exposes JVM thread stack traces - reveals internal class names, business logic paths, and may leak request data",
                &["\"threads\":", "\"threadName\":", "\"stackTrace\":"],
            ),
            (
                "/actuator/beans",
                "Bean Definitions",
                Severity::Medium,
                "Exposes Spring application context bean graph - reveals internal architecture",
                &["\"beans\":", "\"contexts\":"],
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Exposes all URL mappings including hidden admin endpoints",
                &["\"dispatcherServlet\"", "\"dispatcherServlets\"", "\"mappings\""],
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Lists and can modify log levels at runtime; setting DEBUG on auth loggers can leak credentials into log sinks",
                &["\"loggers\"", "\"levels\""],
            ),
            (
                "/actuator/httptrace",
                "HTTP Trace (recent requests)",
                Severity::High,
                "Stores recent HTTP requests including Authorization headers and Cookies, allowing session/credential capture",
                &["\"traces\":", "\"timestamp\":", "\"principal\""],
            ),
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges (recent requests)",
                Severity::High,
                "Boot 3.x replacement for httptrace - exposes recent HTTP requests with headers including session cookies",
                &["\"exchanges\":", "\"request\":", "\"response\":"],
            ),
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::Medium,
                "Exposes authentication audit events - reveals usernames, login times, and failure patterns",
                &["\"events\":", "\"principal\":", "\"type\":\"AUTHENTICATION"],
            ),
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::High,
                "Lists active Spring Session entries by username - reveals signed-in users and session IDs",
                &["\"sessions\":", "\"creationTime\":", "\"lastAccessedTime\":"],
            ),
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Low,
                "Exposes scheduled job class names and cron expressions",
                &["\"cron\":", "\"fixedDelay\":", "\"fixedRate\":"],
            ),
            (
                "/actuator/conditions",
                "Auto-Configuration Conditions",
                Severity::Low,
                "Boot 2+ replacement for /autoconfig - reveals which auto-configurations matched, leaking infra detail",
                &["\"positiveMatches\"", "\"negativeMatches\""],
            ),
            (
                "/actuator/caches",
                "Cache Manager State",
                Severity::Low,
                "Lists all cache names and manager beans",
                &["\"cacheManagers\""],
            ),
            (
                "/actuator/integrationgraph",
                "Integration Graph",
                Severity::Medium,
                "Spring Integration channel/endpoint graph - reveals message-flow architecture",
                &["\"contentDescriptor\"", "\"nodes\":", "\"links\":"],
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changelog",
                Severity::Medium,
                "Exposes database schema migration history - reveals table/column names",
                &["\"liquibaseBeans\"", "\"changeSets\""],
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Exposes Flyway migration history - reveals database schema evolution",
                &["\"flywayBeans\"", "\"migrations\":"],
            ),
            (
                "/actuator/quartz",
                "Quartz Scheduler",
                Severity::Medium,
                "Boot 2.5+ Quartz endpoint - exposes scheduled job definitions",
                &["\"groups\":", "\"jobNames\""],
            ),
            (
                "/actuator/startup",
                "Application Startup Steps",
                Severity::Low,
                "Boot 2.4+ startup tracker - reveals bean initialisation order and internal class graph",
                &["\"timeline\":", "\"startTime\":", "\"events\":"],
            ),
            (
                "/actuator/metrics",
                "Metrics Registry",
                Severity::Low,
                "Exposes Micrometer metric names - allows fingerprinting of internal counters",
                &["\"names\":[", "\"availableTags\""],
            ),
            (
                "/actuator/info",
                "Build/Git Info",
                Severity::Low,
                "Often exposes git commit SHA, branch, build timestamp and dependency versions for targeted CVE matching",
                &["\"git\":", "\"build\":", "\"app\":"],
            ),
            (
                "/actuator/health",
                "Health (with details)",
                Severity::Low,
                "Exposes downstream component status - when management.endpoint.health.show-details=always reveals DB host/Redis cluster names",
                &["\"status\":\"UP", "\"status\":\"DOWN", "\"components\":"],
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP - can read/write MBean attributes and invoke operations, frequently leads to RCE (e.g., Logback JNDI / Spring Cloud Function)",
                &["\"agent\"", "\"value\":{", "\"request\":{\"type\"", "Jolokia Agent"],
            ),
            // --- Spring Cloud Gateway (HIGH-IMPACT, frequent in modern stacks) ---
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::Critical,
                "Lists every gateway route. CVE-2022-22947 (SpEL RCE) and route-injection abuse trivially follow",
                &["\"predicate\":", "\"route_id\":", "\"filters\":"],
            ),
            (
                "/actuator/gateway/globalfilters",
                "Spring Cloud Gateway Global Filters",
                Severity::Medium,
                "Reveals global filter ordering - useful for crafting auth-bypass payloads",
                &["GlobalFilter", "\"order\":"],
            ),
            (
                "/actuator/gateway/routefilters",
                "Spring Cloud Gateway Route Filter Factories",
                Severity::Medium,
                "Lists available route-filter factories - precondition for actuator-add-route attacks",
                &["GatewayFilterFactory", "\"order\":"],
            ),
            // --- Cloud Foundry actuator (Pivotal/VMware Tanzu) ---
            (
                "/cloudfoundryapplication",
                "Cloud Foundry Actuator Root",
                Severity::High,
                "Cloud Foundry actuator namespace - same data as /actuator but historically unauthenticated when JWT verification mis-configured (CVE-2018-1273 pattern)",
                &["\"_links\"", "\"href\""],
            ),
            // --- Spring Boot 1.x legacy (no /actuator prefix) ---
            (
                "/env",
                "Environment (Boot 1.x legacy)",
                Severity::Critical,
                "Legacy environment endpoint - JSON property sources including spring.datasource.password",
                &["\"profiles\":", "\"systemEnvironment\"", "\"applicationConfig:"],
            ),
            (
                "/heapdump",
                "Heap Dump (Boot 1.x legacy)",
                Severity::Critical,
                "Legacy heap dump endpoint - JVM memory dump containing live secrets",
                &[],
            ),
            (
                "/configprops",
                "Config Properties (Boot 1.x legacy)",
                Severity::Critical,
                "Legacy @ConfigurationProperties endpoint",
                &["\"prefix\":", "\"properties\":"],
            ),
            (
                "/trace",
                "HTTP Trace (Boot 1.x legacy)",
                Severity::High,
                "Legacy /trace - recent HTTP request log with headers including Authorization and Cookie",
                &["\"timestamp\":", "\"info\":", "\"headers\":"],
            ),
            (
                "/dump",
                "Thread Dump (Boot 1.x legacy)",
                Severity::High,
                "Legacy thread dump endpoint",
                &["\"threadName\":", "\"stackTrace\":"],
            ),
            (
                "/mappings",
                "URL Mappings (Boot 1.x legacy)",
                Severity::Medium,
                "Legacy URL mappings - reveals all HandlerMappings",
                &["\"bean\":\"requestMapping", "{[/", "produces=["],
            ),
            (
                "/beans",
                "Bean Graph (Boot 1.x legacy)",
                Severity::Medium,
                "Legacy bean graph",
                &["\"beans\":[", "\"scope\":\"singleton"],
            ),
            (
                "/autoconfig",
                "Auto-Configuration Report (Boot 1.x legacy)",
                Severity::Low,
                "Legacy auto-config report",
                &["\"positiveMatches\"", "\"negativeMatches\""],
            ),
            (
                "/loggers",
                "Loggers (Boot 1.x legacy)",
                Severity::High,
                "Legacy loggers endpoint",
                &["\"loggers\"", "\"configuredLevel\""],
            ),
            (
                "/info",
                "Build Info (Boot 1.x legacy)",
                Severity::Low,
                "Legacy /info endpoint - frequently exposes git commit",
                &["\"git\":", "\"build\":"],
            ),
        ];

        for entry in actuator_endpoints {
            let path = entry.0;
            let name = entry.1;
            let severity = entry.2.clone();
            let description = entry.3;
            let anchors = entry.4;
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    // Heap dumps are binary HPROF; a real one starts with the
                    // ASCII magic "JAVA PROFILE". Anything else returning 200
                    // on /heapdump is almost certainly a generic 200 OK page.
                    let is_actuator = if path.contains("heapdump") {
                        response.body.starts_with("JAVA PROFILE")
                            || response.body.as_bytes().windows(12).any(|w| w == b"JAVA PROFILE")
                    } else if !anchors.is_empty() {
                        anchors.iter().any(|a| response.body.contains(a))
                    } else {
                        // No anchors defined and not heapdump: skip rather than
                        // guess. Empty anchor list means "do not auto-report".
                        false
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

        // Springdoc (Boot 3+) ships /v3/api-docs and /swagger-ui/index.html by
        // default; springfox (Boot 2 era) uses /swagger-ui.html and /v2/api-docs.
        // Several springdoc versions also expose /swagger-ui/swagger-ui.css etc.
        // which is enough to confirm the UI is reachable.
        let swagger_paths = vec![
            "/swagger-ui.html",
            "/swagger-ui/",
            "/swagger-ui/index.html",
            "/swagger-ui/swagger-ui.css",
            "/webjars/swagger-ui/index.html",
            "/swagger-resources",
            "/swagger-resources/configuration/ui",
            "/swagger-resources/configuration/security",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs.yaml",
            "/v3/api-docs/swagger-config",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api/swagger.json",
            "/api/v1/swagger.json",
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

        // Spring resolves a long list of config file names at startup (and many
        // deployments ship them straight onto the web root). We probe the
        // canonical forms plus the per-profile variants that are easy to leave
        // exposed when nginx maps a misconfigured static directory.
        let config_paths: &[&str] = &[
            "/application.properties",
            "/application.yml",
            "/application.yaml",
            "/application-dev.properties",
            "/application-dev.yml",
            "/application-prod.properties",
            "/application-prod.yml",
            "/application-production.yml",
            "/application-staging.properties",
            "/application-staging.yml",
            "/application-test.properties",
            "/application-test.yml",
            "/application-local.properties",
            "/application-local.yml",
            // Spring Cloud bootstrap config - usually contains config-server URI
            // and decrypt key material before the main context loads.
            "/bootstrap.properties",
            "/bootstrap.yml",
            "/bootstrap.yaml",
            "/bootstrap-prod.yml",
            // Frequent reverse-proxy mistakes that expose /WEB-INF or /BOOT-INF
            "/WEB-INF/classes/application.properties",
            "/WEB-INF/classes/application.yml",
            "/BOOT-INF/classes/application.properties",
            "/BOOT-INF/classes/application.yml",
        ];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }

                // Require a Spring-specific config key to fire. A bare match on
                // "password" would trip on any JSON API; pairing it with a
                // Spring/JDBC anchor below keeps confidence at High.
                let body_lower = response.body.to_lowercase();
                let spring_anchors = [
                    "spring.datasource",
                    "spring.security",
                    "spring.redis",
                    "spring.rabbitmq",
                    "spring.kafka",
                    "spring.mail",
                    "spring.cloud.config",
                    "spring.profiles.active",
                    "management.endpoints",
                    "server.servlet.context-path",
                    "jdbc:mysql:",
                    "jdbc:postgresql:",
                    "jdbc:oracle:",
                    "jdbc:sqlserver:",
                    "jdbc:h2:",
                    "eureka.client",
                ];
                let secret_anchors = [
                    "password=",
                    "password:",
                    "secret=",
                    "secret:",
                    "private-key",
                    "private_key",
                    "client-secret",
                    "client_secret",
                    "api-key",
                    "api_key",
                ];

                let has_spring = spring_anchors.iter().any(|a| body_lower.contains(a));
                let has_secret = secret_anchors.iter().any(|a| body_lower.contains(a));

                // Avoid flagging HTML responses (e.g., default 404 pages or
                // SPA fallbacks that happen to mention "password").
                let looks_like_html = response.body.trim_start().starts_with('<')
                    || response
                        .headers
                        .get("content-type")
                        .map(|c| c.to_lowercase().contains("text/html"))
                        .unwrap_or(false);

                if has_spring && !looks_like_html {
                    let severity = if has_secret {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    let cvss = if has_secret { 9.1 } else { 7.5 };

                    let matched = spring_anchors
                        .iter()
                        .find(|a| body_lower.contains(**a))
                        .copied()
                        .unwrap_or("spring.*");

                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!("Spring configuration file exposed: {}", path),
                        evidence: Some(format!("Spring property key present: {}", matched)),
                        cwe: "CWE-538".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove configuration files from web-accessible paths; ensure spring-boot-loader / nginx do not serve /WEB-INF or /BOOT-INF"
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
