// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - ASP.NET Core Security Scanner
 * Comprehensive ASP.NET Core / .NET vulnerability detection
 *
 * REQUIRES: Personal license or higher
 *
 * Detects:
 * - ASP.NET framework detection via headers
 * - Yellow Screen of Death (YSOD) detailed error pages
 * - Blazor endpoint exposure
 * - SignalR hub exposure
 * - Development mode indicators
 * - Exposed configuration endpoints
 * - Anti-forgery token issues
 * - Default authentication endpoints
 * - Health check endpoint exposure
 * - Kestrel-specific vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Personal Edition and above
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct AspNetScanner {
    http_client: Arc<HttpClient>,
    known_cves: Vec<AspNetCVE>,
}

#[derive(Clone)]
struct AspNetCVE {
    cve_id: String,
    affected_versions: String,
    severity: Severity,
    description: String,
    check_type: CVECheckType,
}

#[derive(Clone, Debug)]
enum CVECheckType {
    RemoteCodeExecution,
    Denial,
    InformationDisclosure,
    SecurityBypass,
    Spoofing,
    CrossSiteScripting,
}

impl AspNetScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    fn build_cve_database() -> Vec<AspNetCVE> {
        vec![
            AspNetCVE {
                cve_id: "CVE-2024-43498".to_string(),
                affected_versions: ".NET 9.0.0".to_string(),
                severity: Severity::Critical,
                description: "Remote Code Execution vulnerability in .NET NrbfDecoder".to_string(),
                check_type: CVECheckType::RemoteCodeExecution,
            },
            AspNetCVE {
                cve_id: "CVE-2024-43499".to_string(),
                affected_versions: ".NET 9.0.0, 8.0.x".to_string(),
                severity: Severity::High,
                description: "Denial of Service vulnerability in .NET".to_string(),
                check_type: CVECheckType::Denial,
            },
            AspNetCVE {
                cve_id: "CVE-2024-38229".to_string(),
                affected_versions: ".NET 8.0.x, 9.0.0-preview".to_string(),
                severity: Severity::Critical,
                description: "Remote Code Execution in ASP.NET Core Kestrel HTTP/3".to_string(),
                check_type: CVECheckType::RemoteCodeExecution,
            },
            AspNetCVE {
                cve_id: "CVE-2024-38167".to_string(),
                affected_versions: ".NET 8.0.x".to_string(),
                severity: Severity::Medium,
                description: "Information Disclosure vulnerability in .NET".to_string(),
                check_type: CVECheckType::InformationDisclosure,
            },
            AspNetCVE {
                cve_id: "CVE-2024-35264".to_string(),
                affected_versions: ".NET 8.0.x".to_string(),
                severity: Severity::Critical,
                description: "Remote Code Execution in ASP.NET Core".to_string(),
                check_type: CVECheckType::RemoteCodeExecution,
            },
            AspNetCVE {
                cve_id: "CVE-2024-30105".to_string(),
                affected_versions: ".NET 6.0.x, 8.0.x".to_string(),
                severity: Severity::High,
                description: "Denial of Service vulnerability in .NET JSON parsing".to_string(),
                check_type: CVECheckType::Denial,
            },
            AspNetCVE {
                cve_id: "CVE-2024-21319".to_string(),
                affected_versions: ".NET 6.0.x, 7.0.x, 8.0.x".to_string(),
                severity: Severity::Medium,
                description: "Denial of Service vulnerability in ASP.NET Core Identity".to_string(),
                check_type: CVECheckType::Denial,
            },
            AspNetCVE {
                cve_id: "CVE-2023-44487".to_string(),
                affected_versions: ".NET 6.0.x, 7.0.x, 8.0.x".to_string(),
                severity: Severity::High,
                description: "HTTP/2 Rapid Reset Attack (affects Kestrel)".to_string(),
                check_type: CVECheckType::Denial,
            },
            AspNetCVE {
                cve_id: "CVE-2023-36899".to_string(),
                affected_versions: "ASP.NET Core 2.1.x".to_string(),
                severity: Severity::High,
                description: "Security bypass in ASP.NET Core SignalR".to_string(),
                check_type: CVECheckType::SecurityBypass,
            },
            AspNetCVE {
                cve_id: "CVE-2023-33170".to_string(),
                affected_versions: ".NET 6.0.x, 7.0.x".to_string(),
                severity: Severity::High,
                description: "Security bypass in ASP.NET Core authentication".to_string(),
                check_type: CVECheckType::SecurityBypass,
            },
            AspNetCVE {
                cve_id: "CVE-2022-41064".to_string(),
                affected_versions: ".NET 6.0.x".to_string(),
                severity: Severity::Medium,
                description: "Information disclosure in .NET Framework".to_string(),
                check_type: CVECheckType::InformationDisclosure,
            },
            AspNetCVE {
                cve_id: "CVE-2022-38013".to_string(),
                affected_versions: ".NET 6.0.x, .NET Core 3.1.x".to_string(),
                severity: Severity::High,
                description: "Denial of Service in ASP.NET Core SignalR".to_string(),
                check_type: CVECheckType::Denial,
            },
        ]
    }

    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        if !crate::license::has_feature("cms_security") {
            debug!("[ASP.NET] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let (is_aspnet, version_info) = self.detect_aspnet(url).await;

        if !is_aspnet {
            debug!("[ASP.NET] Target does not appear to be running ASP.NET");
            return Ok((vec![], tests_run));
        }

        info!(
            "[ASP.NET] Detected ASP.NET application{}",
            version_info
                .as_ref()
                .map(|v| format!(" ({})", v))
                .unwrap_or_default()
        );

        let (ysod_vulns, ysod_tests) = self.check_ysod_exposure(url, config).await?;
        vulnerabilities.extend(ysod_vulns);
        tests_run += ysod_tests;

        let (blazor_vulns, blazor_tests) = self.check_blazor_exposure(url, config).await?;
        vulnerabilities.extend(blazor_vulns);
        tests_run += blazor_tests;

        let (signalr_vulns, signalr_tests) = self.check_signalr_exposure(url, config).await?;
        vulnerabilities.extend(signalr_vulns);
        tests_run += signalr_tests;

        let (dev_vulns, dev_tests) = self.check_development_mode(url, config).await?;
        vulnerabilities.extend(dev_vulns);
        tests_run += dev_tests;

        let (config_vulns, config_tests) = self.check_config_endpoints(url, config).await?;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        let (csrf_vulns, csrf_tests) = self.check_antiforgery_issues(url, config).await?;
        vulnerabilities.extend(csrf_vulns);
        tests_run += csrf_tests;

        let (auth_vulns, auth_tests) = self.check_auth_endpoints(url, config).await?;
        vulnerabilities.extend(auth_vulns);
        tests_run += auth_tests;

        let (health_vulns, health_tests) = self.check_health_endpoints(url, config).await?;
        vulnerabilities.extend(health_vulns);
        tests_run += health_tests;

        let (kestrel_vulns, kestrel_tests) = self.check_kestrel_issues(url, config).await?;
        vulnerabilities.extend(kestrel_vulns);
        tests_run += kestrel_tests;

        if let Some(ref ver) = version_info {
            let (cve_vulns, cve_tests) = self.check_version_cves(url, ver, config).await?;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!(
            "[ASP.NET] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    async fn detect_aspnet(&self, url: &str) -> (bool, Option<String>) {
        let mut is_aspnet = false;
        let mut version = None;

        if let Ok(resp) = self.http_client.get(url).await {
            if let Some(powered_by) = resp.headers.get("x-powered-by") {
                let powered_lower = powered_by.to_lowercase();
                if powered_lower.contains("asp.net") {
                    is_aspnet = true;
                    if let Some(caps) = Regex::new(r"ASP\.NET[/ ]*([\d.]+)?")
                        .ok()
                        .and_then(|re| re.captures(powered_by))
                    {
                        version = caps.get(1).map(|m| format!("ASP.NET {}", m.as_str()));
                    } else {
                        version = Some("ASP.NET".to_string());
                    }
                }
            }

            if let Some(aspnet_version) = resp.headers.get("x-aspnet-version") {
                is_aspnet = true;
                version = Some(format!("ASP.NET {}", aspnet_version));
            }

            if let Some(aspnetcore_version) = resp.headers.get("x-aspnetcore-version") {
                is_aspnet = true;
                version = Some(format!("ASP.NET Core {}", aspnetcore_version));
            }

            if let Some(server) = resp.headers.get("server") {
                let server_lower = server.to_lowercase();
                if server_lower.contains("kestrel") {
                    is_aspnet = true;
                    if version.is_none() {
                        version = Some("Kestrel".to_string());
                    }
                }
                if server_lower.contains("microsoft-iis") {
                    is_aspnet = true;
                }
            }

            if resp.body.contains("__VIEWSTATE")
                || resp.body.contains("__VIEWSTATEGENERATOR")
                || resp.body.contains("__EVENTVALIDATION")
            {
                is_aspnet = true;
                if version.is_none() {
                    version = Some("ASP.NET WebForms".to_string());
                }
            }

            if resp.body.contains("_blazor")
                || resp.body.contains("blazor.webassembly.js")
                || resp.body.contains("blazor.server.js")
            {
                is_aspnet = true;
                version = Some("ASP.NET Core Blazor".to_string());
            }

            if resp.body.contains("aspnetcore-browser-refresh") {
                is_aspnet = true;
            }
        }

        let aspnet_paths = [
            "/_framework/blazor.server.js",
            "/_framework/blazor.webassembly.js",
            "/signalr/negotiate",
            "/_blazor",
        ];

        for path in aspnet_paths {
            let check_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(resp) = self.http_client.get(&check_url).await {
                if resp.status_code == 200 || resp.status_code == 101 {
                    is_aspnet = true;
                    if path.contains("blazor") && version.is_none() {
                        version = Some("ASP.NET Core Blazor".to_string());
                    }
                    break;
                }
            }
        }

        let error_url = format!(
            "{}/nonexistent-path-trigger-error-12345",
            url.trim_end_matches('/')
        );
        if let Ok(resp) = self.http_client.get(&error_url).await {
            if resp.body.contains("Server Error in")
                || resp.body.contains("ASP.NET")
                || resp.body.contains("System.Web")
                || resp.body.contains("Microsoft.AspNetCore")
            {
                is_aspnet = true;
            }
        }

        (is_aspnet, version)
    }

    async fn check_ysod_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let error_triggers = [
            "/throw-test-exception-12345",
            "/?__invalid__=<script>",
            "/api/../../../etc/passwd",
            "/%00",
            "/?id=1'",
            "/\x00",
            "/.aspx",
            "/web.config",
            "/appsettings.json",
        ];

        for trigger in &error_triggers {
            tests_run += 1;
            let test_url = format!("{}{}", base, trigger);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                let ysod_indicators = [
                    "Server Error in '/' Application",
                    "Runtime Error",
                    "Description: An unhandled exception",
                    "Stack Trace:",
                    "System.Web.HttpException",
                    "Microsoft.AspNetCore",
                    "System.NullReferenceException",
                    "System.InvalidOperationException",
                    "[HttpException]",
                    "[SqlException]",
                    "An error occurred while processing your request",
                    "DeveloperExceptionPageMiddleware",
                    "YSOD",
                ];

                let mut is_ysod = false;
                let mut exposed_info = Vec::new();

                for indicator in &ysod_indicators {
                    if resp.body.contains(indicator) {
                        is_ysod = true;
                        break;
                    }
                }

                if is_ysod {
                    if resp.body.contains("Stack Trace:") || resp.body.contains("at System.") {
                        exposed_info.push("Full stack trace");
                    }
                    if resp.body.contains("Source Error:") || resp.body.contains("Source File:") {
                        exposed_info.push("Source code snippets");
                    }
                    if resp.body.contains("connectionString")
                        || resp.body.contains("Data Source=")
                        || resp.body.contains("Server=")
                    {
                        exposed_info.push("Database connection strings");
                    }
                    if resp.body.contains("web.config")
                        || resp.body.contains("appsettings.json")
                    {
                        exposed_info.push("Configuration file paths");
                    }
                    if resp.body.contains("c:\\") || resp.body.contains("C:\\") || resp.body.contains("/var/www")
                    {
                        exposed_info.push("Server file paths");
                    }
                    if resp.body.contains(".dll") {
                        exposed_info.push("Assembly names");
                    }

                    vulnerabilities.push(Vulnerability {
                        id: format!("aspnet_ysod_{}", Self::generate_id()),
                        vuln_type: "ASP.NET Yellow Screen of Death (YSOD) Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: Some("error_handling".to_string()),
                        payload: trigger.to_string(),
                        description: format!(
                            "ASP.NET detailed error page (YSOD) is exposed in production. \
                            This reveals sensitive application internals including: {}. \
                            Attackers can use this information to identify vulnerabilities \
                            and plan targeted attacks.",
                            if exposed_info.is_empty() {
                                "internal error details".to_string()
                            } else {
                                exposed_info.join(", ")
                            }
                        ),
                        evidence: Some(format!(
                            "Trigger: {}\nExposed: {}",
                            trigger,
                            exposed_info.join(", ")
                        )),
                        cwe: "CWE-209".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Set customErrors mode='On' in web.config (WebForms)\n\
                                      2. Configure app.UseExceptionHandler() in production (Core)\n\
                                      3. Remove app.UseDeveloperExceptionPage() in production\n\
                                      4. Set ASPNETCORE_ENVIRONMENT=Production\n\
                                      5. Implement custom error pages"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_blazor_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let blazor_endpoints = [
            ("/_blazor", "Blazor SignalR Hub"),
            ("/_blazor/negotiate", "Blazor Negotiation Endpoint"),
            ("/_framework/blazor.server.js", "Blazor Server JavaScript"),
            ("/_framework/blazor.webassembly.js", "Blazor WASM JavaScript"),
            ("/_framework/blazor.boot.json", "Blazor Boot Configuration"),
            ("/_content/", "Blazor Static Content"),
            ("/_framework/dotnet.wasm", "WebAssembly Runtime"),
            ("/_framework/blazor.modules.json", "Blazor Modules Manifest"),
        ];

        let mut blazor_detected = false;
        let mut exposed_endpoints = Vec::new();

        for (path, name) in blazor_endpoints {
            tests_run += 1;
            let check_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&check_url).await {
                if resp.status_code == 200 {
                    blazor_detected = true;
                    exposed_endpoints.push((path.to_string(), name.to_string()));

                    if path == "/_framework/blazor.boot.json" {
                        let mut issues = Vec::new();

                        if resp.body.contains("\"assemblies\"") {
                            issues.push("Assembly list exposed");
                        }
                        if resp.body.contains(".pdb") {
                            issues.push("Debug symbols (PDB) references found");
                        }
                        if resp.body.contains("\"debugBuild\"") && resp.body.contains("true") {
                            issues.push("Debug build detected");
                        }

                        if !issues.is_empty() {
                            vulnerabilities.push(Vulnerability {
                                id: format!("aspnet_blazor_boot_{}", Self::generate_id()),
                                vuln_type: "Blazor Boot Configuration Exposed".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                category: "Information Disclosure".to_string(),
                                url: check_url.clone(),
                                parameter: Some("blazor.boot.json".to_string()),
                                payload: path.to_string(),
                                description: format!(
                                    "Blazor boot configuration reveals sensitive build information. \
                                    Issues: {}",
                                    issues.join(", ")
                                ),
                                evidence: Some(format!("Issues found: {}", issues.join(", "))),
                                cwe: "CWE-200".to_string(),
                                cvss: 5.3,
                                verified: true,
                                false_positive: false,
                                remediation:
                                    "1. Ensure release builds are deployed (no debug symbols)\n\
                                    2. Use IL trimming to reduce exposed assemblies\n\
                                    3. Consider obfuscation for sensitive assemblies"
                                        .to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }
        }

        if blazor_detected && !exposed_endpoints.is_empty() {
            let endpoint_list: Vec<String> = exposed_endpoints
                .iter()
                .map(|(p, n)| format!("{} ({})", p, n))
                .collect();

            vulnerabilities.push(Vulnerability {
                id: format!("aspnet_blazor_exposure_{}", Self::generate_id()),
                vuln_type: "Blazor Application Endpoints Exposed".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: Some("blazor".to_string()),
                payload: "/_blazor, /_framework".to_string(),
                description: format!(
                    "Blazor application detected with {} exposed endpoints. \
                    While some exposure is normal, ensure sensitive business logic \
                    is server-validated and not solely reliant on client-side checks.",
                    exposed_endpoints.len()
                ),
                evidence: Some(format!("Endpoints: {}", endpoint_list.join(", "))),
                cwe: "CWE-200".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: "1. Implement server-side validation for all operations\n\
                              2. Use [Authorize] attributes on sensitive components\n\
                              3. Avoid exposing sensitive data in Blazor state\n\
                              4. Consider Blazor Server for sensitive applications"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_signalr_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let signalr_endpoints = [
            "/signalr",
            "/signalr/negotiate",
            "/signalr/hubs",
            "/hubs",
            "/chatHub",
            "/chatHub/negotiate",
            "/notificationHub",
            "/notificationHub/negotiate",
            "/messageHub",
            "/_blazor/negotiate",
        ];

        for path in signalr_endpoints {
            tests_run += 1;
            let check_url = format!("{}{}", base, path);

            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());

            let headers_vec: Vec<(String, String)> =
                headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

            if let Ok(resp) = self.http_client.post_with_headers(&check_url, "{}", headers_vec).await
            {
                let is_signalr = resp.status_code == 200
                    || resp.status_code == 400
                    || resp.body.contains("connectionId")
                    || resp.body.contains("connectionToken")
                    || resp.body.contains("negotiateVersion")
                    || resp.body.contains("availableTransports");

                if is_signalr {
                    let mut issues = Vec::new();

                    if resp.body.contains("WebSockets")
                        && resp.body.contains("ServerSentEvents")
                        && resp.body.contains("LongPolling")
                    {
                        issues.push("All transports enabled");
                    }

                    if !resp.body.contains("accessToken") {
                        issues.push("No authentication configured");
                    }

                    let severity = if path.contains("negotiate") && !issues.is_empty() {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("aspnet_signalr_{}", Self::generate_id()),
                        vuln_type: "SignalR Hub Exposed".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: check_url.clone(),
                        parameter: Some("signalr".to_string()),
                        payload: path.to_string(),
                        description: format!(
                            "SignalR hub endpoint is accessible at {}. {}",
                            path,
                            if issues.is_empty() {
                                "Ensure proper authentication is configured."
                            } else {
                                &format!("Issues: {}", issues.join(", "))
                            }
                        ),
                        evidence: Some(format!(
                            "Endpoint: {}\nResponse: {} bytes",
                            path,
                            resp.body.len()
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: if issues.is_empty() { 3.7 } else { 5.3 },
                        verified: true,
                        false_positive: false,
                        remediation:
                            "1. Implement [Authorize] on hub classes\n\
                            2. Use RequireAuthorization() in hub routing\n\
                            3. Validate user permissions in hub methods\n\
                            4. Consider disabling unnecessary transports"
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_development_mode(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            let mut dev_indicators = Vec::new();

            if resp.body.contains("aspnetcore-browser-refresh.js") {
                dev_indicators.push("Browser refresh script (hot reload)");
            }

            if resp.body.contains("_framework/aspnetcore-browser-refresh.js") {
                dev_indicators.push("ASP.NET Core development browser link");
            }

            if resp.headers.get("x-sourcefiles").is_some() {
                dev_indicators.push("X-SourceFiles header (IIS Express)");
            }

            if let Some(server) = resp.headers.get("server") {
                if server.to_lowercase().contains("development") {
                    dev_indicators.push("Development server header");
                }
            }

            if resp.body.contains("<!-- Hot reload") || resp.body.contains("dotnet watch") {
                dev_indicators.push("Hot reload comments");
            }

            if resp.body.contains("localhost:") || resp.body.contains("127.0.0.1:") {
                let localhost_re = Regex::new(r"(localhost|127\.0\.0\.1):\d{4,5}").ok();
                if let Some(re) = localhost_re {
                    if re.is_match(&resp.body) {
                        dev_indicators.push("Localhost references in production");
                    }
                }
            }

            if !dev_indicators.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: format!("aspnet_dev_mode_{}", Self::generate_id()),
                    vuln_type: "ASP.NET Development Mode Enabled".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Misconfiguration".to_string(),
                    url: url.to_string(),
                    parameter: Some("ASPNETCORE_ENVIRONMENT".to_string()),
                    payload: dev_indicators.join(", "),
                    description: format!(
                        "Application appears to be running in development mode. \
                        Indicators found: {}. Development mode exposes additional \
                        debugging information and may have relaxed security settings.",
                        dev_indicators.join(", ")
                    ),
                    evidence: Some(format!("Indicators: {}", dev_indicators.join(", "))),
                    cwe: "CWE-489".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Set ASPNETCORE_ENVIRONMENT=Production\n\
                                  2. Remove development-only middleware\n\
                                  3. Disable hot reload in production\n\
                                  4. Use proper deployment configuration"
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        tests_run += 1;
        let swagger_paths = [
            "/swagger",
            "/swagger/index.html",
            "/swagger/v1/swagger.json",
            "/api-docs",
        ];

        for path in swagger_paths {
            let swagger_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(resp) = self.http_client.get(&swagger_url).await {
                if resp.status_code == 200
                    && (resp.body.contains("swagger") || resp.body.contains("openapi"))
                {
                    vulnerabilities.push(Vulnerability {
                        id: format!("aspnet_swagger_{}", Self::generate_id()),
                        vuln_type: "Swagger/OpenAPI Documentation Exposed".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: swagger_url.clone(),
                        parameter: Some("swagger".to_string()),
                        payload: path.to_string(),
                        description:
                            "Swagger/OpenAPI documentation is publicly accessible. \
                            This reveals complete API structure, endpoints, and data models."
                                .to_string(),
                        evidence: Some(format!("Swagger UI accessible at: {}", path)),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Disable Swagger in production environments\n\
                                      2. Use conditional: if (app.Environment.IsDevelopment())\n\
                                      3. Add authentication to Swagger endpoints"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_config_endpoints(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let config_paths = [
            ("/web.config", "IIS Configuration", Severity::Critical),
            ("/appsettings.json", "App Settings", Severity::Critical),
            (
                "/appsettings.Development.json",
                "Development Settings",
                Severity::Critical,
            ),
            (
                "/appsettings.Production.json",
                "Production Settings",
                Severity::Critical,
            ),
            ("/connectionstrings.config", "Connection Strings", Severity::Critical),
            ("/applicationhost.config", "IIS App Host Config", Severity::High),
            ("/bin/", "Binary Directory", Severity::Medium),
            ("/obj/", "Build Objects", Severity::Low),
            ("/.vs/", "Visual Studio Directory", Severity::Medium),
            ("/.git/config", "Git Configuration", Severity::High),
            ("/packages.config", "NuGet Packages", Severity::Low),
            ("/nuget.config", "NuGet Configuration", Severity::Medium),
            ("/launchSettings.json", "Launch Settings", Severity::Medium),
            (
                "/Properties/launchSettings.json",
                "Launch Settings",
                Severity::Medium,
            ),
        ];

        for (path, name, severity) in config_paths {
            tests_run += 1;
            let config_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&config_url).await {
                if resp.status_code == 200 && resp.body.len() > 20 {
                    let sensitive_patterns = [
                        "connectionString",
                        "password",
                        "Password",
                        "secret",
                        "Secret",
                        "apiKey",
                        "ApiKey",
                        "Data Source=",
                        "Server=",
                        "User Id=",
                        "Integrated Security",
                        "<authentication",
                        "JWT",
                        "Bearer",
                        "AzureAd",
                        "ClientSecret",
                    ];

                    let has_sensitive = sensitive_patterns
                        .iter()
                        .any(|p| resp.body.contains(p));

                    let final_severity = if has_sensitive {
                        Severity::Critical
                    } else {
                        severity.clone()
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("aspnet_config_{}", Self::generate_id()),
                        vuln_type: format!("ASP.NET {} Exposed", name),
                        severity: final_severity.clone(),
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: config_url.clone(),
                        parameter: Some(path.to_string()),
                        payload: format!("GET {}", path),
                        description: format!(
                            "ASP.NET configuration file ({}) is publicly accessible. {}",
                            name,
                            if has_sensitive {
                                "CRITICAL: Sensitive data (credentials/secrets) detected!"
                            } else {
                                "This may reveal application structure and settings."
                            }
                        ),
                        evidence: Some(format!(
                            "File: {}\nSize: {} bytes\nSensitive data: {}",
                            path,
                            resp.body.len(),
                            has_sensitive
                        )),
                        cwe: if has_sensitive { "CWE-798" } else { "CWE-200" }.to_string(),
                        cvss: match final_severity {
                            Severity::Critical => 9.8,
                            Severity::High => 7.5,
                            Severity::Medium => 5.3,
                            _ => 3.7,
                        },
                        verified: true,
                        false_positive: false,
                        remediation: "1. Configure IIS to block access to config files\n\
                                      2. Use <handlers> and <security> in web.config\n\
                                      3. Store sensitive data in Azure Key Vault or secrets manager\n\
                                      4. Ensure proper file permissions are set"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_antiforgery_issues(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            let has_form = resp.body.contains("<form");

            if has_form {
                let has_antiforgery = resp.body.contains("__RequestVerificationToken")
                    || resp.body.contains("antiforgery")
                    || resp.body.contains("csrf-token")
                    || resp.body.contains("_csrf");

                if !has_antiforgery {
                    vulnerabilities.push(Vulnerability {
                        id: format!("aspnet_csrf_{}", Self::generate_id()),
                        vuln_type: "Missing ASP.NET Anti-Forgery Token".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        category: "CSRF".to_string(),
                        url: url.to_string(),
                        parameter: Some("__RequestVerificationToken".to_string()),
                        payload: "Form without CSRF protection".to_string(),
                        description: "HTML forms detected without ASP.NET anti-forgery tokens. \
                            This may indicate missing CSRF protection on state-changing operations."
                            .to_string(),
                        evidence: Some("Forms found without __RequestVerificationToken".to_string()),
                        cwe: "CWE-352".to_string(),
                        cvss: 6.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Add @Html.AntiForgeryToken() to forms\n\
                                      2. Use [ValidateAntiForgeryToken] on POST actions\n\
                                      3. Configure AutoValidateAntiforgeryToken globally\n\
                                      4. For APIs, use X-XSRF-TOKEN header pattern"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }

            if let Some(cookie) = resp.headers.get("set-cookie") {
                let has_csrf_cookie = cookie.contains(".AspNetCore.Antiforgery")
                    || cookie.contains("XSRF-TOKEN")
                    || cookie.contains("X-CSRF-TOKEN");

                if has_csrf_cookie {
                    let mut issues = Vec::new();

                    if !cookie.to_lowercase().contains("samesite=strict")
                        && !cookie.to_lowercase().contains("samesite=lax")
                    {
                        issues.push("Missing SameSite attribute");
                    }

                    if url.starts_with("https://") && !cookie.to_lowercase().contains("secure") {
                        issues.push("Missing Secure flag on HTTPS");
                    }

                    if !issues.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: format!("aspnet_csrf_cookie_{}", Self::generate_id()),
                            vuln_type: "ASP.NET Anti-Forgery Cookie Misconfiguration".to_string(),
                            severity: Severity::Low,
                            confidence: Confidence::High,
                            category: "CSRF".to_string(),
                            url: url.to_string(),
                            parameter: Some("Antiforgery Cookie".to_string()),
                            payload: issues.join(", "),
                            description: format!(
                                "Anti-forgery cookie has security issues: {}",
                                issues.join(", ")
                            ),
                            evidence: Some(format!("Cookie issues: {}", issues.join(", "))),
                            cwe: "CWE-1004".to_string(),
                            cvss: 3.7,
                            verified: true,
                            false_positive: false,
                            remediation: "Configure antiforgery options in Startup.cs:\n\
                                          services.AddAntiforgery(options => {\n\
                                              options.Cookie.SameSite = SameSiteMode.Strict;\n\
                                              options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n\
                                          });"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_auth_endpoints(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let auth_endpoints = [
            ("/Identity/Account/Login", "ASP.NET Identity Login"),
            ("/Identity/Account/Register", "ASP.NET Identity Register"),
            ("/Identity/Account/ForgotPassword", "Password Reset"),
            ("/Account/Login", "Account Login"),
            ("/Account/Register", "Account Register"),
            ("/connect/token", "OAuth Token Endpoint"),
            ("/connect/authorize", "OAuth Authorize"),
            ("/.well-known/openid-configuration", "OIDC Discovery"),
            ("/oauth2/token", "OAuth2 Token"),
            ("/api/auth/login", "API Auth Login"),
            ("/api/account/register", "API Account Register"),
        ];

        for (path, name) in auth_endpoints {
            tests_run += 1;
            let auth_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&auth_url).await {
                if resp.status_code == 200 || resp.status_code == 405 {
                    if path.contains("well-known") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("aspnet_oidc_{}", Self::generate_id()),
                            vuln_type: "OIDC Configuration Exposed".to_string(),
                            severity: Severity::Low,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: auth_url.clone(),
                            parameter: Some("oidc".to_string()),
                            payload: path.to_string(),
                            description: format!(
                                "{} endpoint is accessible. This reveals authentication \
                                endpoints and supported OAuth flows.",
                                name
                            ),
                            evidence: Some(format!("Endpoint accessible: {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss: 3.7,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "Review OIDC configuration for sensitive information exposure."
                                    .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    } else if path.contains("Register") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("aspnet_registration_{}", Self::generate_id()),
                            vuln_type: "Open Registration Endpoint".to_string(),
                            severity: Severity::Low,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: auth_url.clone(),
                            parameter: Some("registration".to_string()),
                            payload: path.to_string(),
                            description: format!(
                                "{} endpoint is accessible. Verify if public registration is intended.",
                                name
                            ),
                            evidence: Some(format!("Registration page at: {}", path)),
                            cwe: "CWE-287".to_string(),
                            cvss: 3.7,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "1. Disable registration if not needed\n\
                                2. Implement CAPTCHA\n\
                                3. Add email verification\n\
                                4. Implement rate limiting"
                                    .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_health_endpoints(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let health_endpoints = [
            ("/health", "Health Check"),
            ("/healthz", "Health Check (K8s style)"),
            ("/health/ready", "Readiness Probe"),
            ("/health/live", "Liveness Probe"),
            ("/healthchecks", "Health Checks Dashboard"),
            ("/healthchecks-ui", "Health Checks UI"),
            ("/healthchecks-api", "Health Checks API"),
            ("/diagnostics", "Diagnostics"),
            ("/metrics", "Application Metrics"),
            ("/actuator/health", "Actuator Health"),
        ];

        for (path, name) in health_endpoints {
            tests_run += 1;
            let health_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&health_url).await {
                if resp.status_code == 200 {
                    let mut exposed_info = Vec::new();

                    if resp.body.contains("\"status\"")
                        || resp.body.contains("Healthy")
                        || resp.body.contains("Unhealthy")
                        || resp.body.contains("Degraded")
                    {
                        if resp.body.contains("sqlserver")
                            || resp.body.contains("SqlServer")
                            || resp.body.contains("Database")
                        {
                            exposed_info.push("Database health");
                        }
                        if resp.body.contains("redis") || resp.body.contains("Redis") {
                            exposed_info.push("Redis cache status");
                        }
                        if resp.body.contains("rabbitmq") || resp.body.contains("RabbitMQ") {
                            exposed_info.push("RabbitMQ status");
                        }
                        if resp.body.contains("disk") || resp.body.contains("Disk") {
                            exposed_info.push("Disk space info");
                        }
                        if resp.body.contains("memory") || resp.body.contains("Memory") {
                            exposed_info.push("Memory usage");
                        }

                        let severity = if exposed_info.len() > 2 {
                            Severity::Medium
                        } else if !exposed_info.is_empty() {
                            Severity::Low
                        } else {
                            Severity::Info
                        };

                        if severity != Severity::Info {
                            vulnerabilities.push(Vulnerability {
                                id: format!("aspnet_health_{}", Self::generate_id()),
                                vuln_type: format!("ASP.NET {} Endpoint Exposed", name),
                                severity,
                                confidence: Confidence::High,
                                category: "Information Disclosure".to_string(),
                                url: health_url.clone(),
                                parameter: Some("health".to_string()),
                                payload: path.to_string(),
                                description: format!(
                                    "{} endpoint exposes internal system information. {}",
                                    name,
                                    if exposed_info.is_empty() {
                                        "Basic health status visible.".to_string()
                                    } else {
                                        format!("Reveals: {}", exposed_info.join(", "))
                                    }
                                ),
                                evidence: Some(format!(
                                    "Endpoint: {}\nExposed: {}",
                                    path,
                                    if exposed_info.is_empty() {
                                        "Basic status".to_string()
                                    } else {
                                        exposed_info.join(", ")
                                    }
                                )),
                                cwe: "CWE-200".to_string(),
                                cvss: if exposed_info.len() > 2 { 5.3 } else { 3.7 },
                                verified: true,
                                false_positive: false,
                                remediation:
                                    "1. Restrict health endpoints to internal networks\n\
                                    2. Use RequireHost() for localhost-only access\n\
                                    3. Implement authentication on health UI\n\
                                    4. Limit information in health responses"
                                        .to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_kestrel_issues(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            if let Some(server) = resp.headers.get("server") {
                if server.to_lowercase().contains("kestrel") {
                    let mut issues = Vec::new();

                    if resp.headers.get("x-frame-options").is_none()
                        && resp.headers.get("content-security-policy").is_none()
                    {
                        issues.push("Missing clickjacking protection");
                    }

                    if resp.headers.get("x-content-type-options").is_none() {
                        issues.push("Missing X-Content-Type-Options");
                    }

                    if resp.headers.get("strict-transport-security").is_none() && url.starts_with("https://")
                    {
                        issues.push("Missing HSTS header");
                    }

                    if server.to_lowercase() == "kestrel" {
                        issues.push("Kestrel server header exposed");
                    }

                    if !issues.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: format!("aspnet_kestrel_headers_{}", Self::generate_id()),
                            vuln_type: "Kestrel Security Header Issues".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Misconfiguration".to_string(),
                            url: url.to_string(),
                            parameter: Some("Kestrel".to_string()),
                            payload: issues.join(", "),
                            description: format!(
                                "Kestrel web server detected with security issues: {}",
                                issues.join(", ")
                            ),
                            evidence: Some(format!("Server: {}\nIssues: {}", server, issues.join(", "))),
                            cwe: "CWE-16".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Add security headers in Program.cs:\n\
                                          app.UseHsts();\n\
                                          app.Use(async (ctx, next) => {\n\
                                              ctx.Response.Headers.Add(\"X-Frame-Options\", \"DENY\");\n\
                                              ctx.Response.Headers.Add(\"X-Content-Type-Options\", \"nosniff\");\n\
                                              await next();\n\
                                          });"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        tests_run += 1;
        let large_header = "X".repeat(16000);
        let mut headers = HashMap::new();
        headers.insert("X-Test-Large".to_string(), large_header);
        let headers_vec: Vec<(String, String)> =
            headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        if let Ok(resp) = self
            .http_client
            .get_with_headers(url, headers_vec)
            .await
        {
            if resp.status_code == 431 {
                vulnerabilities.push(Vulnerability {
                    id: format!("aspnet_kestrel_limits_{}", Self::generate_id()),
                    vuln_type: "Kestrel Header Size Limits Configured".to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: "Security Configuration".to_string(),
                    url: url.to_string(),
                    parameter: Some("MaxRequestHeadersTotalSize".to_string()),
                    payload: "Large header test".to_string(),
                    description: "Kestrel properly rejects oversized headers. This is good security practice."
                        .to_string(),
                    evidence: Some("HTTP 431 returned for large headers".to_string()),
                    cwe: "CWE-400".to_string(),
                    cvss: 0.0,
                    verified: true,
                    false_positive: false,
                    remediation: "No action needed - header limits are properly configured.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn check_version_cves(
        &self,
        url: &str,
        version_info: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let version_lower = version_info.to_lowercase();

        for cve in &self.known_cves {
            tests_run += 1;

            let affected_lower = cve.affected_versions.to_lowercase();
            let is_potentially_affected = (affected_lower.contains(".net 6")
                && version_lower.contains("6.0"))
                || (affected_lower.contains(".net 7") && version_lower.contains("7.0"))
                || (affected_lower.contains(".net 8") && version_lower.contains("8.0"))
                || (affected_lower.contains(".net 9") && version_lower.contains("9.0"))
                || (affected_lower.contains("core 2") && version_lower.contains("2."))
                || (affected_lower.contains("core 3") && version_lower.contains("3."));

            if is_potentially_affected {
                vulnerabilities.push(Vulnerability {
                    id: format!("aspnet_cve_{}_{}", cve.cve_id, Self::generate_id()),
                    vuln_type: format!("ASP.NET {} - {:?}", cve.cve_id, cve.check_type),
                    severity: cve.severity.clone(),
                    confidence: Confidence::Medium,
                    category: "Known Vulnerability".to_string(),
                    url: url.to_string(),
                    parameter: Some(version_info.to_string()),
                    payload: format!("{}: {}", cve.cve_id, cve.affected_versions),
                    description: format!(
                        "{}\n\nDetected version: {}\nAffected versions: {}",
                        cve.description, version_info, cve.affected_versions
                    ),
                    evidence: Some(format!(
                        "CVE: {}\nVersion: {}\nAffected: {}",
                        cve.cve_id, version_info, cve.affected_versions
                    )),
                    cwe: match cve.check_type {
                        CVECheckType::RemoteCodeExecution => "CWE-94",
                        CVECheckType::Denial => "CWE-400",
                        CVECheckType::InformationDisclosure => "CWE-200",
                        CVECheckType::SecurityBypass => "CWE-287",
                        CVECheckType::Spoofing => "CWE-290",
                        CVECheckType::CrossSiteScripting => "CWE-79",
                    }
                    .to_string(),
                    cvss: match cve.severity {
                        Severity::Critical => 9.8,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.7,
                    },
                    verified: false,
                    false_positive: false,
                    remediation: format!(
                        "Update ASP.NET Core to the latest patched version.\n\
                        See: https://nvd.nist.gov/vuln/detail/{}",
                        cve.cve_id
                    ),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}
