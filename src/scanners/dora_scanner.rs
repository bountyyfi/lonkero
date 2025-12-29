// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - DORA (Digital Operational Resilience Act) Compliance Scanner
 * Comprehensive EU financial services operational resilience assessment
 *
 * REQUIRES: Enterprise license (custom_integrations feature)
 *
 * DORA Compliance Areas Covered:
 * - ICT Risk Management (Article 5-16): Security headers, error handling, access controls
 * - ICT Incident Reporting (Article 17-23): Logging capabilities, monitoring endpoints
 * - Digital Operational Resilience Testing (Article 24-27): Health endpoints, status pages
 * - Third-Party ICT Risk (Article 28-44): External dependencies, CDN/third-party scripts
 * - Information Sharing (Article 45): security.txt, disclosure policies
 * - Business Continuity (implied): Redundancy indicators, failover mechanisms
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// DORA compliance issue categories mapped to regulation articles
#[derive(Debug, Clone)]
pub enum DoraCategory {
    IctRiskManagement,
    IncidentReporting,
    ResilienceTesting,
    ThirdPartyRisk,
    InformationSharing,
    BusinessContinuity,
}

impl DoraCategory {
    fn as_str(&self) -> &'static str {
        match self {
            DoraCategory::IctRiskManagement => "DORA Article 5-16: ICT Risk Management",
            DoraCategory::IncidentReporting => "DORA Article 17-23: ICT Incident Reporting",
            DoraCategory::ResilienceTesting => "DORA Article 24-27: Resilience Testing",
            DoraCategory::ThirdPartyRisk => "DORA Article 28-44: Third-Party ICT Risk",
            DoraCategory::InformationSharing => "DORA Article 45: Information Sharing",
            DoraCategory::BusinessContinuity => "DORA: Business Continuity",
        }
    }
}

/// DORA Compliance Scanner for EU financial services entities
pub struct DoraScanner {
    http_client: Arc<HttpClient>,
    required_security_headers: Vec<(&'static str, &'static str, Severity)>,
    monitoring_endpoints: Vec<&'static str>,
    health_endpoints: Vec<&'static str>,
    risky_cdn_patterns: Vec<(&'static str, &'static str)>,
}

impl DoraScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            required_security_headers: Self::build_required_headers(),
            monitoring_endpoints: Self::build_monitoring_endpoints(),
            health_endpoints: Self::build_health_endpoints(),
            risky_cdn_patterns: Self::build_risky_cdn_patterns(),
        }
    }

    /// Required security headers for DORA ICT risk management compliance
    fn build_required_headers() -> Vec<(&'static str, &'static str, Severity)> {
        vec![
            ("Strict-Transport-Security", "HSTS required for transport security", Severity::High),
            ("Content-Security-Policy", "CSP required for XSS mitigation", Severity::High),
            ("X-Content-Type-Options", "Prevents MIME type sniffing attacks", Severity::Medium),
            ("X-Frame-Options", "Clickjacking protection for financial interfaces", Severity::Medium),
            ("Referrer-Policy", "Prevents sensitive URL leakage", Severity::Low),
            ("Permissions-Policy", "Controls browser feature access", Severity::Low),
            ("Cache-Control", "Sensitive data caching controls", Severity::Medium),
            ("X-XSS-Protection", "Legacy XSS protection header", Severity::Low),
        ]
    }

    /// Common monitoring and logging endpoints to check
    fn build_monitoring_endpoints() -> Vec<&'static str> {
        vec![
            "/metrics",
            "/prometheus",
            "/actuator/prometheus",
            "/actuator/metrics",
            "/_monitoring",
            "/monitoring",
            "/logs",
            "/audit",
            "/audit-log",
            "/events",
            "/incidents",
            "/.well-known/security-events",
        ]
    }

    /// Health and status endpoints for resilience verification
    fn build_health_endpoints() -> Vec<&'static str> {
        vec![
            "/health",
            "/healthz",
            "/healthcheck",
            "/health-check",
            "/ready",
            "/readiness",
            "/live",
            "/liveness",
            "/status",
            "/ping",
            "/actuator/health",
            "/actuator/info",
            "/_health",
            "/api/health",
            "/api/status",
            "/system/health",
        ]
    }

    /// Third-party CDN/script patterns that may introduce supply chain risk
    fn build_risky_cdn_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            ("unpkg.com", "Unpkg CDN - unvetted npm packages"),
            ("jsdelivr.net", "jsDelivr CDN - public repository"),
            ("cdnjs.cloudflare.com", "CDNJS - community-maintained"),
            ("cdn.jsdelivr.net", "jsDelivr CDN mirror"),
            ("rawgit.com", "RawGit - deprecated service"),
            ("raw.githubusercontent.com", "GitHub raw files - no integrity verification"),
            ("gitcdn.xyz", "GitCDN - third-party GitHub mirror"),
            ("statically.io", "Statically CDN - public assets"),
            ("pagecdn.io", "PageCDN - third-party CDN"),
        ]
    }

    /// Main scan entry point
    pub async fn scan(&self, url: &str, config: &ScanConfig) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[DORA] Starting Digital Operational Resilience Act compliance scan");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base_url = self.get_base_url(url);

        // Phase 1: ICT Risk Management Assessment (Articles 5-16)
        let (ict_vulns, ict_tests) = self.assess_ict_risk_management(&base_url).await;
        vulnerabilities.extend(ict_vulns);
        tests_run += ict_tests;

        // Phase 2: Incident Reporting Capabilities (Articles 17-23)
        let (incident_vulns, incident_tests) = self.assess_incident_reporting(&base_url).await;
        vulnerabilities.extend(incident_vulns);
        tests_run += incident_tests;

        // Phase 3: Resilience Testing Indicators (Articles 24-27)
        let (resilience_vulns, resilience_tests) = self.assess_resilience_testing(&base_url).await;
        vulnerabilities.extend(resilience_vulns);
        tests_run += resilience_tests;

        // Phase 4: Third-Party ICT Risk Assessment (Articles 28-44)
        let (third_party_vulns, third_party_tests) = self.assess_third_party_risk(&base_url).await;
        vulnerabilities.extend(third_party_vulns);
        tests_run += third_party_tests;

        // Phase 5: Information Sharing Assessment (Article 45)
        let (info_sharing_vulns, info_sharing_tests) = self.assess_information_sharing(&base_url).await;
        vulnerabilities.extend(info_sharing_vulns);
        tests_run += info_sharing_tests;

        // Phase 6: Business Continuity Assessment
        let (continuity_vulns, continuity_tests) = self.assess_business_continuity(&base_url).await;
        vulnerabilities.extend(continuity_vulns);
        tests_run += continuity_tests;

        // Extended checks for non-fast mode
        if config.scan_mode.as_str() != "fast" {
            // Phase 7: Error Handling Assessment
            let (error_vulns, error_tests) = self.assess_error_handling(&base_url).await;
            vulnerabilities.extend(error_vulns);
            tests_run += error_tests;

            // Phase 8: Authentication & Access Control Indicators
            let (auth_vulns, auth_tests) = self.assess_access_controls(&base_url).await;
            vulnerabilities.extend(auth_vulns);
            tests_run += auth_tests;
        }

        info!(
            "[DORA] Compliance scan complete: {} issues found in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Phase 1: ICT Risk Management Assessment
    async fn assess_ict_risk_management(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing ICT Risk Management (Articles 5-16)");

        // Test 1: Check security headers
        tests_run += 1;
        if let Ok(response) = self.http_client.get(base_url).await {
            let missing_headers: Vec<_> = self.required_security_headers
                .iter()
                .filter(|(header, _, _)| {
                    response.headers.get(&header.to_lowercase()).is_none()
                })
                .collect();

            if !missing_headers.is_empty() {
                let critical_missing: Vec<_> = missing_headers.iter()
                    .filter(|(_, _, sev)| matches!(sev, Severity::High | Severity::Critical))
                    .collect();

                let (severity, cvss_score) = if critical_missing.len() >= 2 {
                    (Severity::High, 7.5)
                } else if !critical_missing.is_empty() {
                    (Severity::Medium, 5.3)
                } else {
                    (Severity::Low, 3.7)
                };

                let missing_list: Vec<String> = missing_headers.iter()
                    .map(|(h, desc, _)| format!("- {}: {}", h, desc))
                    .collect();

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-ICT"),
                    vuln_type: "DORA ICT Risk: Missing Security Headers".to_string(),
                    severity,
                    confidence: Confidence::High,
                    category: DoraCategory::IctRiskManagement.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Security header analysis".to_string(),
                    description: format!(
                        "Missing {} security headers required for DORA ICT risk management compliance.\n\n\
                        DORA Article 9 requires financial entities to implement appropriate ICT security \
                        policies and tools. Missing security headers indicate gaps in technical controls.\n\n\
                        Missing headers:\n{}",
                        missing_headers.len(),
                        missing_list.join("\n")
                    ),
                    evidence: Some(format!("Missing headers: {}", missing_headers.iter().map(|(h, _, _)| *h).collect::<Vec<_>>().join(", "))),
                    cwe: "CWE-693".to_string(),
                    cvss: cvss_score,
                    verified: true,
                    false_positive: false,
                    remediation: "Implement all required security headers:\n\
                        1. Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\
                        2. Content-Security-Policy: Configure appropriate directives\n\
                        3. X-Content-Type-Options: nosniff\n\
                        4. X-Frame-Options: DENY or SAMEORIGIN\n\
                        5. Referrer-Policy: strict-origin-when-cross-origin\n\
                        6. Permissions-Policy: Configure feature restrictions\n\
                        7. Cache-Control: no-store, no-cache for sensitive pages\n\n\
                        Reference: DORA Article 9 - ICT security policies".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Test 2: Check for TLS/HTTPS enforcement
            tests_run += 1;
            let hsts = response.headers.get("strict-transport-security");
            if hsts.is_none() && base_url.starts_with("https://") {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-TLS"),
                    vuln_type: "DORA ICT Risk: No HSTS Enforcement".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: DoraCategory::IctRiskManagement.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "HSTS header check".to_string(),
                    description: "HTTP Strict Transport Security (HSTS) header is not present.\n\n\
                        DORA Article 9(4)(a) requires strong cryptographic controls for data in transit. \
                        Without HSTS, connections may be downgraded to insecure HTTP, exposing \
                        financial data to interception.".to_string(),
                    evidence: Some("Strict-Transport-Security header not found".to_string()),
                    cwe: "CWE-319".to_string(),
                    cvss: 7.4,
                    verified: true,
                    false_positive: false,
                    remediation: "Add HSTS header with appropriate max-age:\n\
                        Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n\
                        Consider HSTS preloading for maximum protection.\n\
                        Reference: DORA Article 9(4)(a)".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Test 3: Check for insecure cookie attributes
            tests_run += 1;
            if let Some(cookies) = response.headers.get("set-cookie") {
                let cookie_lower = cookies.to_lowercase();
                let mut cookie_issues = Vec::new();

                if !cookie_lower.contains("secure") {
                    cookie_issues.push("Missing 'Secure' flag - cookies may be sent over HTTP");
                }
                if !cookie_lower.contains("httponly") {
                    cookie_issues.push("Missing 'HttpOnly' flag - cookies accessible via JavaScript");
                }
                if !cookie_lower.contains("samesite") {
                    cookie_issues.push("Missing 'SameSite' attribute - CSRF risk");
                }

                if !cookie_issues.is_empty() {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("DORA-COOKIE"),
                        vuln_type: "DORA ICT Risk: Insecure Cookie Configuration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: DoraCategory::IctRiskManagement.as_str().to_string(),
                        url: base_url.to_string(),
                        parameter: None,
                        payload: "Cookie security analysis".to_string(),
                        description: format!(
                            "Session cookies lack security attributes required for DORA compliance.\n\n\
                            DORA Article 9 requires protection of ICT assets including session data. \
                            Insecure cookie configuration may lead to session hijacking or data theft.\n\n\
                            Issues found:\n{}",
                            cookie_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                        ),
                        evidence: Some(format!("Cookie header: {}", cookies)),
                        cwe: "CWE-614".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Configure all cookies with security attributes:\n\
                            Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict; Path=/\n\n\
                            For financial applications, always use:\n\
                            - Secure: Ensures HTTPS-only transmission\n\
                            - HttpOnly: Prevents XSS cookie theft\n\
                            - SameSite=Strict: Prevents CSRF attacks".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }

            // Test 4: Server version disclosure
            tests_run += 1;
            let version_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];
            let mut disclosed_versions = Vec::new();

            for header in version_headers {
                if let Some(value) = response.headers.get(header) {
                    if value.contains('/') || value.chars().any(|c| c.is_numeric()) {
                        disclosed_versions.push(format!("{}: {}", header, value));
                    }
                }
            }

            if !disclosed_versions.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-DISC"),
                    vuln_type: "DORA ICT Risk: Server Version Disclosure".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: DoraCategory::IctRiskManagement.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Version disclosure check".to_string(),
                    description: format!(
                        "Server version information is disclosed in response headers.\n\n\
                        DORA Article 9(2) requires minimizing attack surface. Version disclosure \
                        helps attackers identify vulnerable software versions.\n\n\
                        Disclosed information:\n{}",
                        disclosed_versions.join("\n")
                    ),
                    evidence: Some(disclosed_versions.join("; ")),
                    cwe: "CWE-200".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation: "Remove or obfuscate version information from response headers:\n\
                        - Apache: ServerTokens Prod, ServerSignature Off\n\
                        - Nginx: server_tokens off\n\
                        - IIS: Remove X-Powered-By via URL Rewrite\n\
                        - Application: Configure framework to hide version info".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 2: Incident Reporting Capabilities Assessment
    async fn assess_incident_reporting(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Incident Reporting capabilities (Articles 17-23)");

        // Test monitoring endpoints accessibility
        let mut exposed_monitoring = Vec::new();
        let mut _has_monitoring = false;

        for endpoint in &self.monitoring_endpoints {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    _has_monitoring = true;

                    // Check if it exposes sensitive metrics without auth
                    let sensitive_patterns = [
                        "error_count", "exception", "database", "connection",
                        "memory", "cpu", "disk", "credentials", "password",
                        "token", "secret", "key", "internal"
                    ];

                    let body_lower = response.body.to_lowercase();
                    let has_sensitive = sensitive_patterns.iter()
                        .any(|p| body_lower.contains(p));

                    if has_sensitive {
                        exposed_monitoring.push((endpoint.to_string(), response.body.len()));
                    }
                }
            }
        }

        // Report exposed monitoring endpoints
        if !exposed_monitoring.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-MON"),
                vuln_type: "DORA Incident: Exposed Monitoring Endpoints".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: DoraCategory::IncidentReporting.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: exposed_monitoring.iter().map(|(e, _)| e.clone()).collect::<Vec<_>>().join(", "),
                description: format!(
                    "Monitoring endpoints exposing sensitive operational data without authentication.\n\n\
                    DORA Article 17 requires secure incident management. Exposed monitoring can reveal:\n\
                    - Internal system architecture\n\
                    - Error patterns and vulnerabilities\n\
                    - Performance bottlenecks\n\
                    - Potential attack vectors\n\n\
                    Exposed endpoints: {}",
                    exposed_monitoring.len()
                ),
                evidence: Some(exposed_monitoring.iter()
                    .map(|(e, size)| format!("{} ({} bytes)", e, size))
                    .collect::<Vec<_>>()
                    .join(", ")),
                cwe: "CWE-200".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "Secure all monitoring endpoints:\n\
                    1. Implement authentication (OAuth2, mTLS, or API keys)\n\
                    2. Restrict access by IP (internal networks only)\n\
                    3. Use separate ports for monitoring (not exposed to internet)\n\
                    4. Implement network segmentation\n\
                    5. Consider using dedicated monitoring solutions (Prometheus + Grafana with auth)".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Check for incident response headers
        tests_run += 1;
        if let Ok(response) = self.http_client.get(base_url).await {
            let logging_indicators = [
                "x-request-id",
                "x-correlation-id",
                "x-trace-id",
                "traceparent",
                "x-amzn-requestid",
                "x-ms-request-id",
            ];

            let has_tracing = logging_indicators.iter()
                .any(|h| response.headers.get(*h).is_some());

            if !has_tracing {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-TRACE"),
                    vuln_type: "DORA Incident: No Request Tracing Headers".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    category: DoraCategory::IncidentReporting.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Request tracing check".to_string(),
                    description: "No request tracing/correlation headers detected.\n\n\
                        DORA Article 17 requires timely incident detection and response. \
                        Request tracing enables:\n\
                        - Incident investigation and forensics\n\
                        - Root cause analysis\n\
                        - Transaction tracking across services\n\
                        - Compliance audit trails".to_string(),
                    evidence: Some("No X-Request-ID, X-Correlation-ID, or similar headers found".to_string()),
                    cwe: "CWE-778".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation: "Implement distributed tracing:\n\
                        1. Add X-Request-ID or X-Correlation-ID to all responses\n\
                        2. Propagate trace IDs across microservices\n\
                        3. Consider OpenTelemetry/W3C Trace Context standard\n\
                        4. Log trace IDs with all events for correlation".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 3: Resilience Testing Indicators Assessment
    async fn assess_resilience_testing(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Resilience Testing indicators (Articles 24-27)");

        let mut found_health_endpoints = Vec::new();
        let mut exposed_health_details = Vec::new();

        // Test health endpoints
        for endpoint in &self.health_endpoints {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    found_health_endpoints.push(endpoint.to_string());

                    // Check if health endpoint exposes internal details
                    let sensitive_keywords = [
                        "database", "redis", "mongodb", "postgresql", "mysql",
                        "elasticsearch", "kafka", "rabbitmq", "version",
                        "internal", "private", "host", "port", "connection"
                    ];

                    let body_lower = response.body.to_lowercase();
                    let exposed_details: Vec<_> = sensitive_keywords.iter()
                        .filter(|k| body_lower.contains(*k))
                        .map(|k| k.to_string())
                        .collect();

                    if !exposed_details.is_empty() {
                        exposed_health_details.push((endpoint.to_string(), exposed_details));
                    }
                }
            }
        }

        // Check for status page
        tests_run += 1;
        let status_paths = ["/status-page", "/system-status", "/service-status", "/.status"];
        let mut _has_status_page = false;

        for path in status_paths {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.contains("status") || response.body.contains("operational")) {
                    _has_status_page = true;
                    break;
                }
            }
        }

        // Report findings
        if found_health_endpoints.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-HEALTH"),
                vuln_type: "DORA Resilience: No Health Endpoints Detected".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: DoraCategory::ResilienceTesting.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: "Health endpoint enumeration".to_string(),
                description: "No standard health check endpoints detected.\n\n\
                    DORA Article 24 requires regular resilience testing. Health endpoints are essential for:\n\
                    - Automated availability monitoring\n\
                    - Load balancer health checks\n\
                    - Container orchestration (Kubernetes readiness/liveness)\n\
                    - Incident detection and alerting".to_string(),
                evidence: Some("Checked standard paths: /health, /healthz, /ready, /live, /status, etc.".to_string()),
                cwe: "CWE-778".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "Implement standard health check endpoints:\n\
                    1. /health - Overall application health\n\
                    2. /ready - Readiness for traffic\n\
                    3. /live - Liveness (is process running)\n\
                    4. Return appropriate status codes (200 OK, 503 Unavailable)\n\
                    5. Consider Kubernetes health probe patterns".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        if !exposed_health_details.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-HEXP"),
                vuln_type: "DORA Resilience: Health Endpoints Expose Internal Details".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: DoraCategory::ResilienceTesting.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: exposed_health_details.iter()
                    .map(|(e, _)| e.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
                description: format!(
                    "Health endpoints expose internal infrastructure details.\n\n\
                    While health endpoints are necessary for DORA compliance, they should not reveal:\n\
                    - Database connection details\n\
                    - Internal service names\n\
                    - Version information\n\
                    - Network topology\n\n\
                    Exposed details found at {} endpoint(s)",
                    exposed_health_details.len()
                ),
                evidence: Some(exposed_health_details.iter()
                    .map(|(ep, details)| format!("{}: {}", ep, details.join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ")),
                cwe: "CWE-200".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "Minimize information in health responses:\n\
                    1. Return only status (UP/DOWN) for public endpoints\n\
                    2. Use separate authenticated endpoints for detailed health\n\
                    3. Never expose connection strings or credentials\n\
                    4. Consider depth parameter (shallow vs deep health checks)".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 4: Third-Party ICT Risk Assessment
    async fn assess_third_party_risk(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Third-Party ICT Risk (Articles 28-44)");

        tests_run += 1;
        if let Ok(response) = self.http_client.get(base_url).await {
            let body = &response.body;

            // Find external scripts
            let script_re = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).ok();
            let _link_re = Regex::new(r#"<link[^>]*href=["']([^"']+)["']"#).ok();

            let mut external_resources: HashMap<String, Vec<String>> = HashMap::new();
            let mut risky_resources: Vec<(String, String)> = Vec::new();
            let mut missing_integrity = Vec::new();

            // Analyze scripts
            if let Some(re) = &script_re {
                for cap in re.captures_iter(body) {
                    if let Some(src) = cap.get(1) {
                        let url = src.as_str();
                        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("//") {
                            // Check for risky CDNs
                            for (pattern, description) in &self.risky_cdn_patterns {
                                if url.contains(pattern) {
                                    risky_resources.push((url.to_string(), description.to_string()));
                                }
                            }

                            // Extract domain
                            let domain = url.split('/').nth(2).unwrap_or("unknown").to_string();
                            external_resources.entry(domain.clone())
                                .or_insert_with(Vec::new)
                                .push(url.to_string());

                            // Check for SRI (Subresource Integrity)
                            let script_tag_end = body.find(url)
                                .and_then(|pos| body[pos..].find('>'))
                                .map(|end| &body[..body.find(url).unwrap_or(0) + end]);

                            if let Some(tag) = script_tag_end {
                                if !tag.contains("integrity=") {
                                    missing_integrity.push(url.to_string());
                                }
                            }
                        }
                    }
                }
            }

            // Report risky third-party resources
            if !risky_resources.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-3P"),
                    vuln_type: "DORA Third-Party: High-Risk External Dependencies".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: DoraCategory::ThirdPartyRisk.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "External resource analysis".to_string(),
                    description: format!(
                        "High-risk third-party resources detected from public CDNs.\n\n\
                        DORA Article 28 requires assessment of ICT third-party risk. Public CDNs pose risks:\n\
                        - Supply chain attacks (compromised packages)\n\
                        - No contractual guarantees\n\
                        - Limited security auditing\n\
                        - Service availability concerns\n\n\
                        Found {} risky external resources:\n{}",
                        risky_resources.len(),
                        risky_resources.iter()
                            .map(|(url, desc)| format!("- {} ({})", url, desc))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                    evidence: Some(risky_resources.iter()
                        .map(|(url, _)| url.clone())
                        .collect::<Vec<_>>()
                        .join(", ")),
                    cwe: "CWE-829".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Mitigate third-party ICT risk:\n\
                        1. Self-host critical JavaScript libraries\n\
                        2. Use enterprise CDN with SLA (CloudFront, Azure CDN)\n\
                        3. Implement Subresource Integrity (SRI) for all external resources\n\
                        4. Maintain inventory of third-party dependencies\n\
                        5. Conduct due diligence on CDN providers per DORA Article 28\n\
                        6. Include CDN providers in ICT third-party register".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Report missing SRI
            if !missing_integrity.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-SRI"),
                    vuln_type: "DORA Third-Party: Missing Subresource Integrity".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: DoraCategory::ThirdPartyRisk.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "SRI check".to_string(),
                    description: format!(
                        "External scripts loaded without Subresource Integrity (SRI) hashes.\n\n\
                        DORA Article 9 requires ensuring integrity of ICT systems. Without SRI:\n\
                        - Compromised CDNs can serve malicious code\n\
                        - Man-in-the-middle attacks can inject scripts\n\
                        - No verification of script authenticity\n\n\
                        {} external scripts without integrity verification",
                        missing_integrity.len()
                    ),
                    evidence: Some(missing_integrity.iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")),
                    cwe: "CWE-353".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "Implement Subresource Integrity for all external resources:\n\
                        <script src=\"https://cdn.example.com/lib.js\"\n\
                               integrity=\"sha384-...\"\n\
                               crossorigin=\"anonymous\"></script>\n\n\
                        Generate SRI hashes using: https://www.srihash.org/\n\
                        Or via command line: openssl dgst -sha384 -binary file.js | openssl base64 -A".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Report high number of external dependencies
            if external_resources.len() > 5 {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-DEP"),
                    vuln_type: "DORA Third-Party: Multiple External Dependencies".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: DoraCategory::ThirdPartyRisk.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Dependency count analysis".to_string(),
                    description: format!(
                        "Application loads resources from {} different external domains.\n\n\
                        DORA Article 28-44 requires managing third-party ICT risk. \
                        Each external dependency:\n\
                        - Increases attack surface\n\
                        - Adds potential failure points\n\
                        - Requires due diligence and monitoring\n\
                        - Should be in ICT third-party register\n\n\
                        External domains: {}",
                        external_resources.len(),
                        external_resources.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                    evidence: Some(format!("{} external domains", external_resources.len())),
                    cwe: "CWE-1104".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation: "Reduce and manage external dependencies:\n\
                        1. Consolidate to fewer, trusted providers\n\
                        2. Self-host where possible\n\
                        3. Maintain ICT third-party register per DORA Article 28(3)\n\
                        4. Conduct risk assessment for each provider\n\
                        5. Ensure contractual arrangements per DORA Article 30".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 5: Information Sharing Assessment
    async fn assess_information_sharing(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Information Sharing (Article 45)");

        // Test 1: Check for security.txt
        tests_run += 1;
        let security_txt_paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ];

        let mut has_security_txt = false;
        let mut security_txt_issues = Vec::new();

        for path in security_txt_paths {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.contains("Contact:") {
                    has_security_txt = true;
                    let content = &response.body;

                    // Validate security.txt content
                    if !content.contains("Expires:") {
                        security_txt_issues.push("Missing 'Expires:' field (required by RFC 9116)");
                    }
                    if !content.contains("Encryption:") && !content.contains("encryption:") {
                        security_txt_issues.push("Missing 'Encryption:' field for secure communication");
                    }
                    if !content.contains("Preferred-Languages:") {
                        security_txt_issues.push("Missing 'Preferred-Languages:' field");
                    }
                    if !content.contains("Policy:") {
                        security_txt_issues.push("Missing 'Policy:' field linking to disclosure policy");
                    }
                    break;
                }
            }
        }

        if !has_security_txt {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-SEC"),
                vuln_type: "DORA Information: Missing security.txt".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: DoraCategory::InformationSharing.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: "security.txt check".to_string(),
                description: "No security.txt file found at standard locations.\n\n\
                    DORA Article 45 encourages information sharing. security.txt (RFC 9116):\n\
                    - Enables responsible vulnerability disclosure\n\
                    - Provides security contact information\n\
                    - Demonstrates security maturity\n\
                    - Facilitates coordination with security researchers".to_string(),
                evidence: Some("Checked /.well-known/security.txt and /security.txt".to_string()),
                cwe: "CWE-1059".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: "Create security.txt at /.well-known/security.txt:\n\n\
                    Contact: mailto:security@example.com\n\
                    Expires: 2025-12-31T23:59:59.000Z\n\
                    Encryption: https://example.com/pgp-key.txt\n\
                    Preferred-Languages: en, fi\n\
                    Canonical: https://example.com/.well-known/security.txt\n\
                    Policy: https://example.com/security-policy\n\n\
                    Reference: RFC 9116, DORA Article 45".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        } else if !security_txt_issues.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-SECV"),
                vuln_type: "DORA Information: Incomplete security.txt".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: DoraCategory::InformationSharing.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: "security.txt validation".to_string(),
                description: format!(
                    "security.txt exists but is missing recommended fields.\n\n\
                    Issues found:\n{}",
                    security_txt_issues.iter()
                        .map(|i| format!("- {}", i))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
                evidence: Some(security_txt_issues.join("; ")),
                cwe: "CWE-1059".to_string(),
                cvss: 2.0,
                verified: true,
                false_positive: false,
                remediation: "Update security.txt with all recommended fields:\n\
                    - Expires: (required) - File expiration date\n\
                    - Encryption: - PGP key for encrypted communication\n\
                    - Preferred-Languages: - Accepted languages for reports\n\
                    - Policy: - Link to disclosure policy\n\
                    - Acknowledgments: - Link to hall of fame".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Test 2: Check for disclosure policy
        tests_run += 1;
        let disclosure_paths = [
            "/security-policy",
            "/responsible-disclosure",
            "/vulnerability-disclosure",
            "/bug-bounty",
            "/.well-known/security-policy",
        ];

        let mut has_disclosure_policy = false;
        for path in disclosure_paths {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.to_lowercase().contains("disclosure") ||
                    response.body.to_lowercase().contains("vulnerability") ||
                    response.body.to_lowercase().contains("security")) {
                    has_disclosure_policy = true;
                    break;
                }
            }
        }

        if !has_disclosure_policy {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("DORA-POL"),
                vuln_type: "DORA Information: No Vulnerability Disclosure Policy".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: DoraCategory::InformationSharing.as_str().to_string(),
                url: base_url.to_string(),
                parameter: None,
                payload: "Disclosure policy check".to_string(),
                description: "No public vulnerability disclosure policy detected.\n\n\
                    DORA encourages information sharing arrangements. A disclosure policy:\n\
                    - Defines how researchers can report vulnerabilities\n\
                    - Sets expectations for response times\n\
                    - Provides legal safe harbor for researchers\n\
                    - Demonstrates security program maturity".to_string(),
                evidence: Some("No disclosure policy found at standard locations".to_string()),
                cwe: "CWE-1059".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: "Publish a vulnerability disclosure policy covering:\n\
                    1. Scope of assets covered\n\
                    2. How to report vulnerabilities\n\
                    3. Expected response timelines\n\
                    4. Safe harbor statement\n\
                    5. Recognition/rewards (if applicable)\n\n\
                    Consider ISO 29147 guidelines for vulnerability disclosure".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 6: Business Continuity Assessment
    async fn assess_business_continuity(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Business Continuity indicators");

        tests_run += 1;
        if let Ok(response) = self.http_client.get(base_url).await {
            // Check for redundancy/failover indicators in headers
            let redundancy_headers = [
                "x-served-by",
                "x-backend-server",
                "x-cache",
                "x-cdn-pop",
                "cf-ray",
                "x-amz-cf-id",
                "x-azure-ref",
                "via",
            ];

            let mut _found_headers = Vec::new();
            for header in redundancy_headers {
                if let Some(value) = response.headers.get(header) {
                    _found_headers.push((header.to_string(), value.clone()));
                }
            }

            // Check for single point of failure indicators
            let has_cdn = response.headers.get("cf-ray").is_some() ||
                         response.headers.get("x-cdn-pop").is_some() ||
                         response.headers.get("x-amz-cf-id").is_some() ||
                         response.headers.get("x-azure-ref").is_some();

            let has_cache = response.headers.get("x-cache").is_some() ||
                           response.headers.get("age").is_some();

            if !has_cdn && !has_cache {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-CDN"),
                    vuln_type: "DORA Continuity: No CDN/Caching Layer Detected".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Low,
                    category: DoraCategory::BusinessContinuity.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Infrastructure resilience check".to_string(),
                    description: "No CDN or caching layer indicators detected.\n\n\
                        DORA requires operational resilience including:\n\
                        - Redundant infrastructure\n\
                        - Geographic distribution\n\
                        - DDoS protection\n\
                        - Failover capabilities\n\n\
                        CDNs provide these capabilities by default.".to_string(),
                    evidence: Some("No CDN headers (CF-Ray, X-CDN-Pop, etc.) detected".to_string()),
                    cwe: "CWE-400".to_string(),
                    cvss: 3.7,
                    verified: false,
                    false_positive: false,
                    remediation: "Consider implementing CDN for resilience:\n\
                        1. CloudFront, CloudFlare, Azure CDN, or similar\n\
                        2. Configure caching for static assets\n\
                        3. Enable DDoS protection features\n\
                        4. Set up geographic distribution\n\
                        5. Configure failover origins".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for backup/failover headers
            tests_run += 1;
            if response.headers.get("retry-after").is_some() ||
               response.headers.get("x-ratelimit-remaining").is_some() {
                // Good - has rate limiting/retry logic
            } else {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("DORA-RATE"),
                    vuln_type: "DORA Continuity: No Rate Limiting Headers".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Low,
                    category: DoraCategory::BusinessContinuity.as_str().to_string(),
                    url: base_url.to_string(),
                    parameter: None,
                    payload: "Rate limiting check".to_string(),
                    description: "No rate limiting headers detected in response.\n\n\
                        Rate limiting is important for operational resilience:\n\
                        - Prevents resource exhaustion\n\
                        - Mitigates DoS attacks\n\
                        - Ensures fair resource allocation\n\
                        - Required for API availability".to_string(),
                    evidence: Some("No X-RateLimit-* or Retry-After headers found".to_string()),
                    cwe: "CWE-770".to_string(),
                    cvss: 3.7,
                    verified: false,
                    false_positive: false,
                    remediation: "Implement rate limiting with standard headers:\n\
                        X-RateLimit-Limit: 100\n\
                        X-RateLimit-Remaining: 99\n\
                        X-RateLimit-Reset: 1640000000\n\
                        Retry-After: 60 (when limit exceeded)\n\n\
                        Use API gateway or reverse proxy for implementation".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 7: Error Handling Assessment
    async fn assess_error_handling(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Error Handling");

        // Test various error conditions
        let error_paths = [
            "/nonexistent-page-12345",
            "/api/nonexistent",
            "/%00",
            "/..%252f",
        ];

        for path in error_paths {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&test_url).await {
                let body_lower = response.body.to_lowercase();

                // Check for stack traces or debug info
                let debug_indicators = [
                    "stack trace",
                    "stacktrace",
                    "exception",
                    "error in",
                    "at line",
                    "debug",
                    "traceback",
                    "caused by:",
                    "root cause:",
                    "sql syntax",
                    "mysql",
                    "postgresql",
                    "oracle",
                    "sqlserver",
                    "internal server error",
                    "asp.net",
                    "php error",
                    "python traceback",
                    "java.lang",
                    "node.js",
                    "typeerror:",
                    "referenceerror:",
                ];

                let mut found_debug = Vec::new();
                for indicator in debug_indicators {
                    if body_lower.contains(indicator) {
                        found_debug.push(indicator.to_string());
                    }
                }

                if !found_debug.is_empty() {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("DORA-ERR"),
                        vuln_type: "DORA ICT Risk: Verbose Error Messages".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: DoraCategory::IctRiskManagement.as_str().to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Application exposes detailed error information.\n\n\
                            DORA Article 9 requires minimizing information disclosure. Verbose errors:\n\
                            - Reveal internal architecture\n\
                            - Expose technology stack details\n\
                            - May contain file paths or database info\n\
                            - Help attackers craft exploits\n\n\
                            Debug indicators found: {}",
                            found_debug.join(", ")
                        ),
                        evidence: Some(format!("Response contains: {}", found_debug.join(", "))),
                        cwe: "CWE-209".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Implement proper error handling:\n\
                            1. Use generic error messages for users\n\
                            2. Log detailed errors server-side only\n\
                            3. Disable debug mode in production\n\
                            4. Configure custom error pages\n\
                            5. Never expose stack traces publicly".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Phase 8: Access Controls Assessment
    async fn assess_access_controls(&self, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[DORA] Assessing Access Controls indicators");

        // Check authentication-related headers and paths
        tests_run += 1;
        if let Ok(_response) = self.http_client.get(base_url).await {
            // Check for exposed admin paths
            let admin_paths = [
                "/admin",
                "/administrator",
                "/wp-admin",
                "/console",
                "/management",
                "/manager",
            ];

            for path in admin_paths {
                let test_url = format!("{}{}", base_url.trim_end_matches('/'), path);
                tests_run += 1;

                if let Ok(admin_response) = self.http_client.get(&test_url).await {
                    // Check if admin panel is accessible without auth
                    if admin_response.status_code == 200 {
                        let has_login = admin_response.body.to_lowercase().contains("login") ||
                                       admin_response.body.to_lowercase().contains("sign in") ||
                                       admin_response.body.to_lowercase().contains("password");

                        if !has_login {
                            vulnerabilities.push(Vulnerability {
                                id: generate_vuln_id("DORA-ADMIN"),
                                vuln_type: "DORA ICT Risk: Potentially Unprotected Admin Path".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                category: DoraCategory::IctRiskManagement.as_str().to_string(),
                                url: test_url.clone(),
                                parameter: None,
                                payload: path.to_string(),
                                description: format!(
                                    "Administrative path {} returns 200 without apparent authentication.\n\n\
                                    DORA Article 9 requires strong access controls. Unprotected admin:\n\
                                    - Allows unauthorized system changes\n\
                                    - Violates least privilege principle\n\
                                    - May expose sensitive operations",
                                    path
                                ),
                                evidence: Some(format!("Path {} returned HTTP 200", path)),
                                cwe: "CWE-306".to_string(),
                                cvss: 7.5,
                                verified: false,
                                false_positive: false,
                                remediation: "Secure administrative interfaces:\n\
                                    1. Require strong authentication\n\
                                    2. Implement MFA for admin access\n\
                                    3. Restrict by IP/VPN\n\
                                    4. Use separate admin domains\n\
                                    5. Audit all admin actions".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Helper: Extract base URL from full URL
    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("localhost");
            let scheme = parsed.scheme();
            if let Some(port) = parsed.port() {
                format!("{}://{}:{}", scheme, host, port)
            } else {
                format!("{}://{}", scheme, host)
            }
        } else {
            url.to_string()
        }
    }
}

/// Generate unique vulnerability ID
fn generate_vuln_id(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{:x}", prefix, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_id_generation() {
        let id1 = generate_vuln_id("DORA-TEST");
        let id2 = generate_vuln_id("DORA-TEST");
        assert!(id1.starts_with("DORA-TEST-"));
        assert!(id2.starts_with("DORA-TEST-"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_dora_category_strings() {
        assert_eq!(DoraCategory::IctRiskManagement.as_str(), "DORA Article 5-16: ICT Risk Management");
        assert_eq!(DoraCategory::IncidentReporting.as_str(), "DORA Article 17-23: ICT Incident Reporting");
        assert_eq!(DoraCategory::ResilienceTesting.as_str(), "DORA Article 24-27: Resilience Testing");
        assert_eq!(DoraCategory::ThirdPartyRisk.as_str(), "DORA Article 28-44: Third-Party ICT Risk");
        assert_eq!(DoraCategory::InformationSharing.as_str(), "DORA Article 45: Information Sharing");
        assert_eq!(DoraCategory::BusinessContinuity.as_str(), "DORA: Business Continuity");
    }
}
