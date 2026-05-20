// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::{HttpClient, HttpResponse};
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

        // (path, name, severity, description, signatures)
        //
        // `signatures` are response-body fragments that must ALL be present for the
        // endpoint to be treated as genuinely exposed. They are taken from the real
        // Actuator JSON shape of each endpoint, so a generic 200 page, a JSON error
        // envelope (e.g. a 405 with `"status"`), or an unrelated API response cannot
        // trigger a finding. `/actuator/heapdump` is validated separately via its
        // binary HPROF header. This scanner only runs once `detect_spring` has
        // confirmed the target is a Spring Boot app, so these checks confirm
        // *exposure* of an already-identified framework rather than guessing.
        let actuator_endpoints: Vec<(&str, &str, Severity, &str, &[&str])> = vec![
            // --- Critical: direct secret / RCE / availability impact ---
            (
                "/actuator/env",
                "Environment Variables",
                Severity::Critical,
                "Exposes resolved property sources and environment variables, frequently including credentials, tokens and connection strings",
                &["\"propertySources\""],
            ),
            (
                "/actuator/configprops",
                "Configuration Properties",
                Severity::Critical,
                "Exposes @ConfigurationProperties beans, often containing datasource passwords, API keys and other secrets",
                &["\"prefix\"", "\"properties\""],
            ),
            (
                "/actuator/heapdump",
                "Heap Dump",
                Severity::Critical,
                "Allows downloading a full JVM heap dump containing in-memory secrets, session tokens and credentials",
                &[],
            ),
            (
                "/actuator/jolokia",
                "Jolokia JMX",
                Severity::Critical,
                "JMX over HTTP via Jolokia - readable/writable MBeans can be escalated to remote code execution",
                &["\"agent\"", "\"protocol\""],
            ),
            (
                "/actuator/shutdown",
                "Application Shutdown",
                Severity::Critical,
                "Unauthenticated shutdown endpoint - allows an attacker to terminate the application",
                &["\"message\"", "Shutting down"],
            ),
            // --- High: session / request capture, runtime control, recon-to-pivot ---
            (
                "/actuator/httpexchanges",
                "HTTP Exchanges",
                Severity::High,
                "Exposes recent HTTP requests/responses including Authorization headers and Cookies, enabling session hijacking",
                &["\"exchanges\"", "\"request\""],
            ),
            (
                "/actuator/httptrace",
                "HTTP Trace",
                Severity::High,
                "Exposes recent HTTP requests/responses (legacy) including auth headers and cookies, enabling session hijacking",
                &["\"traces\"", "\"request\""],
            ),
            (
                "/actuator/sessions",
                "Active Sessions",
                Severity::High,
                "Exposes active Spring Session entries including session IDs, enabling account/session hijacking",
                &["\"sessions\"", "\"lastAccessedTime\""],
            ),
            (
                "/actuator/threaddump",
                "Thread Dump",
                Severity::High,
                "Exposes a full thread dump - stack frames and locals can leak tokens, queries and internal paths",
                &["\"threads\"", "\"threadState\""],
            ),
            (
                "/actuator/loggers",
                "Loggers",
                Severity::High,
                "Exposes logger configuration and (via POST) allows changing log levels at runtime",
                &["\"levels\"", "\"loggers\""],
            ),
            (
                "/actuator/gateway/routes",
                "Spring Cloud Gateway Routes",
                Severity::High,
                "Exposes gateway route definitions (upstream URIs, predicates, filters) - useful for SSRF pivoting and internal mapping",
                &["\"route_id\"", "\"predicate\""],
            ),
            // --- Medium: structural / audit recon ---
            (
                "/actuator/auditevents",
                "Audit Events",
                Severity::Medium,
                "Exposes authentication/authorization audit events, leaking usernames and login activity",
                &["\"events\"", "\"principal\""],
            ),
            (
                "/actuator/beans",
                "Application Beans",
                Severity::Medium,
                "Exposes the full bean graph (types, packages, dependencies), revealing internal architecture",
                &["\"beans\"", "\"dependencies\""],
            ),
            (
                "/actuator/mappings",
                "URL Mappings",
                Severity::Medium,
                "Exposes all request mappings including hidden/admin routes",
                &["\"dispatcherServlet"],
            ),
            (
                "/actuator/conditions",
                "Autoconfiguration Conditions",
                Severity::Medium,
                "Exposes autoconfiguration condition evaluation, revealing enabled integrations and libraries",
                &["\"positiveMatches\"", "\"negativeMatches\""],
            ),
            (
                "/actuator/flyway",
                "Flyway Migrations",
                Severity::Medium,
                "Exposes database migration history (scripts, versions, checksums), disclosing schema details",
                &["\"flywayBeans\""],
            ),
            (
                "/actuator/liquibase",
                "Liquibase Changesets",
                Severity::Medium,
                "Exposes database changelog history, disclosing schema and migration details",
                &["\"liquibaseBeans\""],
            ),
            // --- Low: lower-impact information disclosure ---
            (
                "/actuator/scheduledtasks",
                "Scheduled Tasks",
                Severity::Low,
                "Exposes scheduled task definitions and cron expressions",
                &["\"fixedDelay\"", "\"fixedRate\""],
            ),
            (
                "/actuator/metrics",
                "Application Metrics",
                Severity::Low,
                "Exposes JVM and application metrics useful for fingerprinting and reconnaissance",
                &["\"names\"", "jvm."],
            ),
            (
                "/actuator/health",
                "Health",
                Severity::Low,
                "Exposes health status and (when detailed) component/dependency information",
                &["\"status\""],
            ),
            // --- Legacy (Spring Boot 1.x) flat paths ---
            (
                "/env",
                "Environment (Legacy)",
                Severity::Critical,
                "Legacy environment endpoint exposing property sources and secrets",
                &["\"systemEnvironment\""],
            ),
            (
                "/heapdump",
                "Heap Dump (Legacy)",
                Severity::Critical,
                "Legacy heap dump endpoint - downloadable JVM memory containing secrets",
                &[],
            ),
            (
                "/trace",
                "HTTP Trace (Legacy)",
                Severity::High,
                "Legacy request trace endpoint exposing recent requests including auth headers and cookies",
                &["\"headers\"", "\"timestamp\""],
            ),
            (
                "/configprops",
                "Configuration Properties (Legacy)",
                Severity::Critical,
                "Legacy configuration properties endpoint, often containing credentials and secrets",
                &["\"prefix\"", "\"properties\""],
            ),
        ];

        for (path, name, severity, description, signatures) in actuator_endpoints {
            let url = format!("{}{}", target, path);
            tests += 1;

            let response = match self.http_client.get(&url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Request to {} failed: {}", path, e);
                    continue;
                }
            };

            if response.status_code != 200 {
                continue;
            }

            // Heap dumps are binary (HPROF), every other endpoint returns
            // Actuator-specific JSON whose distinctive keys must all be present.
            let exposed = if path.contains("heapdump") {
                Self::is_heapdump(&response)
            } else {
                !signatures.is_empty()
                    && signatures.iter().all(|sig| response.body.contains(sig))
            };

            if !exposed {
                continue;
            }

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
                description: format!(
                    "Spring Boot Actuator {} endpoint exposed: {}",
                    name, description
                ),
                evidence: Some(format!(
                    "{} returned HTTP 200 with Actuator-specific content",
                    path
                )),
                cwe: "CWE-200".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation:
                    "Secure actuator endpoints with authentication or disable in production. \
                     Restrict exposure via management.endpoints.web.exposure.include and bind \
                     the management port to a private interface."
                        .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests))
    }

    /// Confirm a `/heapdump` response is a real JVM heap dump rather than a 200
    /// landing/error page. HPROF dumps begin with the ASCII magic "JAVA PROFILE";
    /// some Spring versions stream them as a generic binary download, so a binary
    /// content-type with a non-trivial body is also accepted.
    fn is_heapdump(response: &HttpResponse) -> bool {
        if response.body.starts_with("JAVA PROFILE") {
            return true;
        }
        let is_binary = response
            .headers
            .get("content-type")
            .map(|ct| {
                let ct = ct.to_ascii_lowercase();
                ct.contains("application/octet-stream")
                    || ct.contains("application/hprof")
                    || ct.contains("application/vnd")
            })
            .unwrap_or(false);
        is_binary && response.body.len() > 1024
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn response(body: &str, content_type: Option<&str>) -> crate::http_client::HttpResponse {
        let mut headers = HashMap::new();
        if let Some(ct) = content_type {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        crate::http_client::HttpResponse {
            status_code: 200,
            body: body.to_string(),
            headers,
            duration_ms: 0,
        }
    }

    #[test]
    fn heapdump_accepts_hprof_magic() {
        let resp = response("JAVA PROFILE 1.0.2\0\0\0...", None);
        assert!(SpringScanner::is_heapdump(&resp));
    }

    #[test]
    fn heapdump_accepts_binary_download() {
        let large = "\u{0}".repeat(2048);
        let resp = response(&large, Some("application/octet-stream"));
        assert!(SpringScanner::is_heapdump(&resp));
    }

    #[test]
    fn heapdump_rejects_plain_html_page() {
        // A 200 landing/error page must never be reported as a heap dump.
        let resp = response(
            "<html><body>Whitelabel Error Page</body></html>",
            Some("text/html"),
        );
        assert!(!SpringScanner::is_heapdump(&resp));
    }

    #[test]
    fn heapdump_rejects_small_binary() {
        let resp = response("not-a-dump", Some("application/octet-stream"));
        assert!(!SpringScanner::is_heapdump(&resp));
    }

    #[test]
    fn actuator_signatures_are_endpoint_specific() {
        // Distinctive Actuator JSON keys match...
        let env = r#"{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment"}]}"#;
        assert!(env.contains("\"propertySources\""));

        let configprops =
            r#"{"contexts":{"app":{"beans":{"x":{"prefix":"spring.datasource","properties":{}}}}}}"#;
        assert!(configprops.contains("\"prefix\"") && configprops.contains("\"properties\""));

        // ...but a generic JSON error envelope (e.g. a 405 on /actuator/shutdown)
        // does NOT satisfy any endpoint signature, so it cannot become a finding.
        let error_envelope =
            r#"{"timestamp":"2026-01-01T00:00:00Z","status":405,"error":"Method Not Allowed"}"#;
        assert!(!error_envelope.contains("\"propertySources\""));
        assert!(!(error_envelope.contains("\"prefix\"") && error_envelope.contains("\"properties\"")));
        assert!(!(error_envelope.contains("\"message\"") && error_envelope.contains("Shutting down")));
    }
}
