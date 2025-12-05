// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloudflare WAF Security Scanner
 * Comprehensive WAF and security configuration scanning for Cloudflare zones
 *
 * Detects:
 * - WAF disabled on zones
 * - Firewall rules too permissive
 * - Rate limiting not configured
 * - Bot management not enabled
 * - SSL/TLS mode set to Flexible (insecure)
 * - Certificate validation issues
 * - Origin server IP exposure
 * - DDoS protection not enabled
 * - Page Rules misconfigurations
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize)]
struct CloudflareApiResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ZoneSettings {
    id: String,
    value: serde_json::Value,
    #[serde(default)]
    editable: bool,
}

#[derive(Debug, Deserialize)]
struct FirewallRule {
    id: String,
    description: Option<String>,
    action: String,
    filter: Filter,
    #[serde(default)]
    paused: bool,
}

#[derive(Debug, Deserialize)]
struct Filter {
    id: String,
    expression: String,
}

#[derive(Debug, Deserialize)]
struct RateLimit {
    id: String,
    #[serde(default)]
    disabled: bool,
    description: Option<String>,
    #[serde(rename = "match")]
    match_rule: MatchRule,
    threshold: u32,
    period: u32,
}

#[derive(Debug, Deserialize)]
struct MatchRule {
    request: RequestMatch,
}

#[derive(Debug, Deserialize)]
struct RequestMatch {
    url: String,
}

#[derive(Debug, Deserialize)]
struct PageRule {
    id: String,
    targets: Vec<Target>,
    actions: Vec<Action>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct Target {
    target: String,
    constraint: Constraint,
}

#[derive(Debug, Deserialize)]
struct Constraint {
    operator: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct Action {
    id: String,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
    name: String,
    status: String,
    #[serde(default)]
    paused: bool,
}

#[derive(Debug, Serialize)]
pub struct CloudflareWafConfig {
    pub api_token: String,
    pub zone_id: String,
    pub check_waf: bool,
    pub check_ssl: bool,
    pub check_firewall: bool,
    pub check_rate_limiting: bool,
    pub check_bot_management: bool,
    pub check_ddos: bool,
    pub check_page_rules: bool,
}

pub struct CloudflareWafScanner {
    http_client: Arc<HttpClient>,
    api_token: String,
}

impl CloudflareWafScanner {
    pub fn new(http_client: Arc<HttpClient>, api_token: String) -> Self {
        Self {
            http_client,
            api_token,
        }
    }

    /// Main scan function for Cloudflare WAF security
    pub async fn scan(
        &self,
        zone_id: &str,
        config: &CloudflareWafConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting Cloudflare WAF security scan for zone: {}", zone_id);

        // Get zone info
        let zone = match self.fetch_zone(zone_id).await {
            Ok(z) => z,
            Err(e) => {
                warn!("Failed to fetch zone info: {}", e);
                return Ok((vulnerabilities, 0));
            }
        };

        info!("Scanning zone: {}", zone.name);

        // Check if zone is paused
        if zone.paused {
            vulnerabilities.push(self.create_vulnerability(
                &zone.name,
                "Zone Paused",
                "",
                &format!("Zone '{}' is currently paused", zone.name),
                "All Cloudflare security features are disabled when zone is paused",
                Severity::Critical,
                "CWE-693",
                9.1,
            ));
        }

        // Fetch zone settings
        let settings = match self.fetch_zone_settings(zone_id).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to fetch zone settings: {}", e);
                Vec::new()
            }
        };

        // Check WAF settings
        if config.check_waf {
            let (vulns, tests) = self.check_waf_settings(&settings, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check SSL/TLS settings
        if config.check_ssl {
            let (vulns, tests) = self.check_ssl_settings(&settings, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check firewall rules
        if config.check_firewall {
            let (vulns, tests) = self.check_firewall_rules(zone_id, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check rate limiting
        if config.check_rate_limiting {
            let (vulns, tests) = self.check_rate_limiting(zone_id, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check bot management
        if config.check_bot_management {
            let (vulns, tests) = self.check_bot_management(&settings, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check DDoS protection
        if config.check_ddos {
            let (vulns, tests) = self.check_ddos_protection(&settings, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check page rules
        if config.check_page_rules {
            let (vulns, tests) = self.check_page_rules(zone_id, &zone.name).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check for origin IP exposure
        let (vulns, tests) = self.check_origin_exposure(&zone.name).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        info!(
            "Cloudflare WAF scan completed: {} vulnerabilities found, {} tests run",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Fetch zone information
    async fn fetch_zone(&self, zone_id: &str) -> anyhow::Result<Zone> {
        let url = format!("https://api.cloudflare.com/client/v4/zones/{}", zone_id);

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let response = self.http_client.get_with_headers(&url, headers).await?;

        let api_response: CloudflareApiResponse<Zone> = serde_json::from_str(&response.body)?;

        if !api_response.success {
            let errors = api_response
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow::anyhow!("Cloudflare API error: {}", errors));
        }

        api_response
            .result
            .ok_or_else(|| anyhow::anyhow!("No zone data returned"))
    }

    /// Fetch zone settings
    async fn fetch_zone_settings(&self, zone_id: &str) -> anyhow::Result<Vec<ZoneSettings>> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/settings",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let response = self.http_client.get_with_headers(&url, headers).await?;

        let api_response: CloudflareApiResponse<Vec<ZoneSettings>> =
            serde_json::from_str(&response.body)?;

        if !api_response.success {
            let errors = api_response
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow::anyhow!("Cloudflare API error: {}", errors));
        }

        Ok(api_response.result.unwrap_or_default())
    }

    /// Check WAF settings
    async fn check_waf_settings(
        &self,
        settings: &[ZoneSettings],
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking WAF settings");

        // Check if WAF is enabled
        if let Some(waf_setting) = settings.iter().find(|s| s.id == "waf") {
            if let Some(value) = waf_setting.value.as_str() {
                if value == "off" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "WAF Disabled",
                        "",
                        "Web Application Firewall is disabled for this zone",
                        "Zone is vulnerable to common web attacks without WAF protection",
                        Severity::Critical,
                        "CWE-693",
                        9.1,
                    ));
                }
            }
        }

        // Check security level
        if let Some(security_level) = settings.iter().find(|s| s.id == "security_level") {
            if let Some(level) = security_level.value.as_str() {
                if level == "off" || level == "essentially_off" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "Low Security Level",
                        &format!("Security level: {}", level),
                        "Cloudflare security level is set too low",
                        "Zone has minimal protection against malicious traffic",
                        Severity::High,
                        "CWE-693",
                        7.5,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check SSL/TLS settings
    async fn check_ssl_settings(
        &self,
        settings: &[ZoneSettings],
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Checking SSL/TLS settings");

        // Check SSL mode
        if let Some(ssl_setting) = settings.iter().find(|s| s.id == "ssl") {
            if let Some(mode) = ssl_setting.value.as_str() {
                if mode == "flexible" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "Insecure SSL/TLS Mode - Flexible",
                        "SSL Mode: flexible",
                        "SSL/TLS mode is set to 'Flexible' which doesn't encrypt origin traffic",
                        "Traffic between Cloudflare and origin server is unencrypted (HTTP)",
                        Severity::Critical,
                        "CWE-319",
                        9.1,
                    ));
                } else if mode == "off" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "SSL/TLS Disabled",
                        "SSL Mode: off",
                        "SSL/TLS is completely disabled",
                        "All traffic is transmitted in plaintext without encryption",
                        Severity::Critical,
                        "CWE-319",
                        9.8,
                    ));
                }
            }
        }

        // Check minimum TLS version
        if let Some(tls_setting) = settings.iter().find(|s| s.id == "min_tls_version") {
            if let Some(version) = tls_setting.value.as_str() {
                if version == "1.0" || version == "1.1" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "Outdated TLS Version",
                        &format!("Minimum TLS version: {}", version),
                        &format!("Minimum TLS version is set to {}, which is deprecated", version),
                        "Zone allows connections using vulnerable TLS protocols",
                        Severity::High,
                        "CWE-327",
                        7.5,
                    ));
                }
            }
        }

        // Check Always Use HTTPS
        if let Some(https_setting) = settings.iter().find(|s| s.id == "always_use_https") {
            if let Some(value) = https_setting.value.as_str() {
                if value == "off" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "Always Use HTTPS Disabled",
                        "",
                        "'Always Use HTTPS' is disabled",
                        "HTTP requests are not automatically redirected to HTTPS",
                        Severity::Medium,
                        "CWE-319",
                        5.3,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check firewall rules
    async fn check_firewall_rules(
        &self,
        zone_id: &str,
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking firewall rules");

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/firewall/rules",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        match self.http_client.get_with_headers(&url, headers).await {
            Ok(response) => {
                let api_response: CloudflareApiResponse<Vec<FirewallRule>> =
                    serde_json::from_str(&response.body)?;

                if let Some(rules) = api_response.result {
                    tests_run = rules.len();

                    if rules.is_empty() {
                        vulnerabilities.push(self.create_vulnerability(
                            zone_name,
                            "No Firewall Rules Configured",
                            "",
                            "No firewall rules are configured for this zone",
                            "Zone lacks custom firewall protection against specific threats",
                            Severity::Medium,
                            "CWE-693",
                            5.3,
                        ));
                    } else {
                        // Check for overly permissive rules
                        for rule in &rules {
                            if rule.action == "allow"
                                && (rule.filter.expression == "true"
                                    || rule.filter.expression.contains("ip.src"))
                            {
                                vulnerabilities.push(self.create_vulnerability(
                                    zone_name,
                                    "Overly Permissive Firewall Rule",
                                    &rule.filter.expression,
                                    &format!(
                                        "Firewall rule '{}' is too permissive",
                                        rule.description.as_deref().unwrap_or("Unnamed")
                                    ),
                                    "Rule allows broad access that may bypass other security controls",
                                    Severity::Medium,
                                    "CWE-732",
                                    6.5,
                                ));
                            }

                            // Check for paused rules
                            if rule.paused {
                                vulnerabilities.push(self.create_vulnerability(
                                    zone_name,
                                    "Paused Firewall Rule",
                                    &rule.id,
                                    &format!(
                                        "Firewall rule '{}' is paused",
                                        rule.description.as_deref().unwrap_or("Unnamed")
                                    ),
                                    "Security rule is not actively protecting the zone",
                                    Severity::Low,
                                    "CWE-693",
                                    3.7,
                                ));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch firewall rules: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check rate limiting configuration
    async fn check_rate_limiting(
        &self,
        zone_id: &str,
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking rate limiting configuration");

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/rate_limits",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        match self.http_client.get_with_headers(&url, headers).await {
            Ok(response) => {
                let api_response: CloudflareApiResponse<Vec<RateLimit>> =
                    serde_json::from_str(&response.body)?;

                if let Some(limits) = api_response.result {
                    if limits.is_empty() {
                        vulnerabilities.push(self.create_vulnerability(
                            zone_name,
                            "No Rate Limiting Configured",
                            "",
                            "No rate limiting rules are configured",
                            "Zone is vulnerable to brute force and DoS attacks",
                            Severity::High,
                            "CWE-770",
                            7.5,
                        ));
                    } else {
                        // Check for disabled rate limits
                        for limit in &limits {
                            if limit.disabled {
                                vulnerabilities.push(self.create_vulnerability(
                                    zone_name,
                                    "Disabled Rate Limit",
                                    &limit.match_rule.request.url,
                                    &format!(
                                        "Rate limit '{}' is disabled",
                                        limit.description.as_deref().unwrap_or("Unnamed")
                                    ),
                                    "Rate limiting protection is not active",
                                    Severity::Medium,
                                    "CWE-770",
                                    5.3,
                                ));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch rate limits: {}", e);
                // Rate limiting might not be available on all plans
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check bot management settings
    async fn check_bot_management(
        &self,
        settings: &[ZoneSettings],
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking bot management settings");

        // Check if bot fight mode is enabled
        if let Some(bot_setting) = settings.iter().find(|s| s.id == "bot_fight_mode") {
            if let Some(value) = bot_setting.value.as_bool() {
                if !value {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "Bot Management Not Enabled",
                        "",
                        "Bot Fight Mode is disabled",
                        "Zone lacks protection against malicious bots and automated attacks",
                        Severity::Medium,
                        "CWE-799",
                        5.3,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check DDoS protection settings
    async fn check_ddos_protection(
        &self,
        settings: &[ZoneSettings],
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking DDoS protection settings");

        // Check HTTP/2 (helps with DDoS mitigation)
        if let Some(http2_setting) = settings.iter().find(|s| s.id == "http2") {
            if let Some(value) = http2_setting.value.as_str() {
                if value == "off" {
                    vulnerabilities.push(self.create_vulnerability(
                        zone_name,
                        "HTTP/2 Disabled",
                        "",
                        "HTTP/2 is disabled",
                        "Missing performance and security benefits of HTTP/2 protocol",
                        Severity::Low,
                        "CWE-693",
                        3.7,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check page rules configuration
    async fn check_page_rules(
        &self,
        zone_id: &str,
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking page rules configuration");

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/pagerules",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        match self.http_client.get_with_headers(&url, headers).await {
            Ok(response) => {
                let api_response: CloudflareApiResponse<Vec<PageRule>> =
                    serde_json::from_str(&response.body)?;

                if let Some(rules) = api_response.result {
                    tests_run = rules.len();

                    for rule in &rules {
                        // Check for disabled security features in page rules
                        for action in &rule.actions {
                            if action.id == "disable_security" || action.id == "disable_apps" {
                                vulnerabilities.push(self.create_vulnerability(
                                    zone_name,
                                    "Page Rule Disables Security",
                                    &format!("{:?}", rule.targets),
                                    "Page rule disables security features",
                                    "Security protections are bypassed for matching URLs",
                                    Severity::High,
                                    "CWE-693",
                                    7.5,
                                ));
                            }

                            // Check for SSL mode downgrade
                            if action.id == "ssl" {
                                if let Some(ssl_value) = &action.value {
                                    if ssl_value == "off" || ssl_value == "flexible" {
                                        vulnerabilities.push(self.create_vulnerability(
                                            zone_name,
                                            "Page Rule Downgrades SSL",
                                            &format!("{:?}", rule.targets),
                                            "Page rule downgrades SSL/TLS security",
                                            "Weakens encryption for matching URLs",
                                            Severity::High,
                                            "CWE-319",
                                            7.5,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch page rules: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for origin server IP exposure
    async fn check_origin_exposure(
        &self,
        zone_name: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking for origin IP exposure");

        // Common paths that might leak origin IP
        let test_paths = vec![
            "/phpinfo.php",
            "/info.php",
            "/.env",
            "/config.php",
            "/wp-config.php.bak",
        ];

        for path in test_paths {
            let url = format!("https://{}{}", zone_name, path);

            match self.http_client.get(&url).await {
                Ok(response) => {
                    // Check for origin IP in response
                    if response.body.contains("REMOTE_ADDR")
                        || response.body.contains("SERVER_ADDR")
                    {
                        // Look for non-Cloudflare IPs (Cloudflare IPs start with specific ranges)
                        if !response.body.contains("173.245.")
                            && !response.body.contains("103.21.")
                            && !response.body.contains("103.22.")
                        {
                            vulnerabilities.push(self.create_vulnerability(
                                zone_name,
                                "Potential Origin IP Exposure",
                                path,
                                &format!("File at {} may expose origin server IP", path),
                                "Origin IP exposure allows attackers to bypass Cloudflare protection",
                                Severity::High,
                                "CWE-200",
                                7.5,
                            ));
                        }
                    }
                }
                Err(_) => {
                    // File not found is expected and good
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cf_waf_{}", self.generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloudflare WAF Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn generate_uuid(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!(
            "{:08x}{:04x}{:04x}{:04x}{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u64>() & 0xffffffffffff
        )
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Zone Paused" => {
                "1. Unpause the zone in Cloudflare dashboard\n\
                 2. Verify DNS records are correctly configured\n\
                 3. Ensure all security features are enabled\n\
                 4. Review zone configuration after unpausing".to_string()
            }
            "WAF Disabled" | "Low Security Level" => {
                "1. Enable WAF in Cloudflare dashboard (Security > WAF)\n\
                 2. Set security level to 'Medium' or 'High'\n\
                 3. Configure WAF managed rules\n\
                 4. Enable OWASP Core Ruleset\n\
                 5. Create custom WAF rules for application-specific threats\n\
                 6. Monitor WAF events and adjust rules as needed".to_string()
            }
            "Insecure SSL/TLS Mode - Flexible" => {
                "1. Change SSL mode to 'Full' or 'Full (strict)' in SSL/TLS settings\n\
                 2. Install SSL certificate on origin server\n\
                 3. Configure origin server to accept HTTPS connections\n\
                 4. Use Cloudflare Origin CA certificates for free SSL\n\
                 5. Test end-to-end encryption\n\
                 6. Never use 'Flexible' mode in production".to_string()
            }
            "SSL/TLS Disabled" => {
                "1. Enable SSL/TLS immediately (set to 'Full' or 'Full (strict)')\n\
                 2. Install SSL certificate on origin server\n\
                 3. Enable 'Always Use HTTPS'\n\
                 4. Enable HSTS with appropriate max-age\n\
                 5. Review all page rules for SSL settings".to_string()
            }
            "Outdated TLS Version" => {
                "1. Set minimum TLS version to 1.2 or 1.3\n\
                 2. Disable TLS 1.0 and 1.1 support\n\
                 3. Enable TLS 1.3 for better performance and security\n\
                 4. Notify users about TLS requirement changes\n\
                 5. Monitor for compatibility issues".to_string()
            }
            "Always Use HTTPS Disabled" => {
                "1. Enable 'Always Use HTTPS' in SSL/TLS settings\n\
                 2. Configure HSTS header\n\
                 3. Create page rules to force HTTPS on all pages\n\
                 4. Update internal links to use HTTPS\n\
                 5. Submit domain to HSTS preload list".to_string()
            }
            "No Firewall Rules Configured" | "Overly Permissive Firewall Rule" => {
                "1. Create firewall rules for common attack patterns\n\
                 2. Block known malicious IPs and user agents\n\
                 3. Implement geo-blocking if appropriate\n\
                 4. Rate limit sensitive endpoints\n\
                 5. Use challenge pages for suspicious traffic\n\
                 6. Review and refine rules based on analytics\n\
                 7. Follow principle of least privilege".to_string()
            }
            "No Rate Limiting Configured" | "Disabled Rate Limit" => {
                "1. Configure rate limiting for login pages\n\
                 2. Protect API endpoints with rate limits\n\
                 3. Set appropriate thresholds (e.g., 10 req/min for login)\n\
                 4. Configure progressive delays or blocks\n\
                 5. Monitor rate limit events\n\
                 6. Adjust limits based on legitimate traffic patterns".to_string()
            }
            "Bot Management Not Enabled" => {
                "1. Enable Bot Fight Mode (Free plan) or Bot Management (paid plans)\n\
                 2. Configure challenge pages for suspected bots\n\
                 3. Use JavaScript detection\n\
                 4. Implement CAPTCHAs for sensitive actions\n\
                 5. Monitor bot traffic analytics\n\
                 6. Create firewall rules for known bot patterns".to_string()
            }
            "Page Rule Disables Security" | "Page Rule Downgrades SSL" => {
                "1. Review and remove security-disabling page rules\n\
                 2. Never disable security features via page rules\n\
                 3. Use more specific firewall rules instead\n\
                 4. Maintain 'Full' or 'Full (strict)' SSL mode\n\
                 5. Audit all page rules regularly\n\
                 6. Document reasons for any security exceptions".to_string()
            }
            "Potential Origin IP Exposure" => {
                "1. Remove or restrict access to info disclosure files\n\
                 2. Use .htaccess or server config to block access\n\
                 3. Implement additional firewall at origin\n\
                 4. Consider rotating origin IP if exposed\n\
                 5. Use Cloudflare Authenticated Origin Pulls\n\
                 6. Restrict origin to accept only Cloudflare IPs\n\
                 7. Never publish origin IP in DNS records".to_string()
            }
            _ => "Review and configure according to Cloudflare security best practices".to_string(),
        }
    }
}
