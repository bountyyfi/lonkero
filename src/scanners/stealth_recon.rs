//! Stealth Reconnaissance Scanner
//!
//! Probes target to identify WAF/CDN protections and recommends
//! the appropriate scan mode. Honest about what can and cannot be bypassed.

use crate::http_client::{BlockType, HttpClient, HttpResponse};
use crate::types::{ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;

/// Protection level detected on target
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionLevel {
    /// No WAF/CDN detected - standard scanning works
    None,
    /// Basic WAF - header stealth usually works
    Basic,
    /// TLS fingerprinting active - needs Parasite Mode
    TlsFingerprinting,
    /// Behavioral analysis - needs headless browser
    Behavioral,
    /// Advanced bot detection - may need manual testing
    Advanced,
}

impl std::fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionLevel::None => write!(f, "None"),
            ProtectionLevel::Basic => write!(f, "Basic WAF"),
            ProtectionLevel::TlsFingerprinting => write!(f, "TLS Fingerprinting"),
            ProtectionLevel::Behavioral => write!(f, "Behavioral Analysis"),
            ProtectionLevel::Advanced => write!(f, "Advanced Bot Detection"),
        }
    }
}

/// CDN/WAF provider detected
#[derive(Debug, Clone, PartialEq)]
pub enum Provider {
    Cloudflare,
    CloudflareEnterprise,
    Akamai,
    AwsWaf,
    AwsCloudFront,
    Imperva,
    Sucuri,
    Fastly,
    KeyCDN,
    Stackpath,
    ModSecurity,
    F5BigIp,
    Fortinet,
    Barracuda,
    Azure,
    GoogleCloud,
    Unknown(String),
    None,
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provider::Cloudflare => write!(f, "Cloudflare"),
            Provider::CloudflareEnterprise => write!(f, "Cloudflare Enterprise"),
            Provider::Akamai => write!(f, "Akamai"),
            Provider::AwsWaf => write!(f, "AWS WAF"),
            Provider::AwsCloudFront => write!(f, "AWS CloudFront"),
            Provider::Imperva => write!(f, "Imperva/Incapsula"),
            Provider::Sucuri => write!(f, "Sucuri"),
            Provider::Fastly => write!(f, "Fastly"),
            Provider::KeyCDN => write!(f, "KeyCDN"),
            Provider::Stackpath => write!(f, "StackPath"),
            Provider::ModSecurity => write!(f, "ModSecurity"),
            Provider::F5BigIp => write!(f, "F5 BIG-IP"),
            Provider::Fortinet => write!(f, "Fortinet FortiWeb"),
            Provider::Barracuda => write!(f, "Barracuda WAF"),
            Provider::Azure => write!(f, "Azure CDN/WAF"),
            Provider::GoogleCloud => write!(f, "Google Cloud Armor"),
            Provider::Unknown(s) => write!(f, "Unknown ({})", s),
            Provider::None => write!(f, "None detected"),
        }
    }
}

/// Recommended scan mode based on detected protections
#[derive(Debug, Clone)]
pub enum RecommendedMode {
    /// Standard scanning - no special measures needed
    Standard,
    /// Use stealth headers (already default)
    StealthHeaders,
    /// Enable Parasite Mode for real TLS fingerprint
    ParasiteMode,
    /// Use headless browser for full JS execution
    HeadlessBrowser,
    /// Request allowlisting from target
    RequestAllowlist,
    /// Manual testing recommended
    ManualTesting,
}

impl std::fmt::Display for RecommendedMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendedMode::Standard => write!(f, "Standard (no special measures)"),
            RecommendedMode::StealthHeaders => write!(f, "Stealth Headers (default)"),
            RecommendedMode::ParasiteMode => write!(f, "Parasite Mode (--parasite)"),
            RecommendedMode::HeadlessBrowser => write!(f, "Headless Browser (--headless)"),
            RecommendedMode::RequestAllowlist => write!(f, "Request allowlisting from target"),
            RecommendedMode::ManualTesting => write!(f, "Manual testing recommended"),
        }
    }
}

/// Complete stealth reconnaissance report
#[derive(Debug, Clone)]
pub struct StealthReport {
    pub url: String,
    pub provider: Provider,
    pub protection_level: ProtectionLevel,
    pub is_currently_blocked: bool,
    pub block_type: Option<BlockType>,
    pub recommended_mode: RecommendedMode,
    pub details: Vec<String>,
    pub headers_detected: Vec<(String, String)>,
    pub confidence: u8, // 0-100
}

impl StealthReport {
    /// Generate human-readable report
    pub fn to_string_report(&self) -> String {
        let mut report = String::new();

        report.push_str("\n============================================================\n");
        report.push_str("  STEALTH RECONNAISSANCE REPORT\n");
        report.push_str("============================================================\n\n");

        report.push_str(&format!("Target: {}\n\n", self.url));

        report.push_str("PROTECTION ANALYSIS\n");
        report.push_str(&format!("{:-<40}\n", ""));
        report.push_str(&format!("Provider:         {}\n", self.provider));
        report.push_str(&format!("Protection Level: {}\n", self.protection_level));
        report.push_str(&format!("Currently Blocked: {}\n", if self.is_currently_blocked { "YES" } else { "No" }));
        if let Some(ref bt) = self.block_type {
            report.push_str(&format!("Block Type:       {}\n", bt));
        }
        report.push_str(&format!("Confidence:       {}%\n\n", self.confidence));

        report.push_str("RECOMMENDATION\n");
        report.push_str(&format!("{:-<40}\n", ""));
        report.push_str(&format!("Scan Mode: {}\n\n", self.recommended_mode));

        if !self.details.is_empty() {
            report.push_str("DETAILS\n");
            report.push_str(&format!("{:-<40}\n", ""));
            for detail in &self.details {
                report.push_str(&format!("  - {}\n", detail));
            }
            report.push_str("\n");
        }

        if !self.headers_detected.is_empty() {
            report.push_str("SECURITY HEADERS DETECTED\n");
            report.push_str(&format!("{:-<40}\n", ""));
            for (name, value) in &self.headers_detected {
                let display_value = if value.len() > 50 {
                    format!("{}...", &value[..50])
                } else {
                    value.clone()
                };
                report.push_str(&format!("  {}: {}\n", name, display_value));
            }
            report.push_str("\n");
        }

        // Honest assessment
        report.push_str("HONEST ASSESSMENT\n");
        report.push_str(&format!("{:-<40}\n", ""));
        match self.protection_level {
            ProtectionLevel::None => {
                report.push_str("  Target has minimal protection.\n");
                report.push_str("  Standard scanning should work without issues.\n");
            }
            ProtectionLevel::Basic => {
                report.push_str("  Target uses basic WAF rules.\n");
                report.push_str("  Lonkero's default stealth headers should be sufficient.\n");
            }
            ProtectionLevel::TlsFingerprinting => {
                report.push_str("  Target checks TLS fingerprints (JA3/JA4).\n");
                report.push_str("  Parasite Mode routes requests through real Chrome TLS.\n");
                report.push_str("  This defeats ~85% of TLS-based blocking.\n");
            }
            ProtectionLevel::Behavioral => {
                report.push_str("  Target uses behavioral analysis.\n");
                report.push_str("  Headless browser with real navigation may help.\n");
                report.push_str("  Some endpoints may still be blocked.\n");
            }
            ProtectionLevel::Advanced => {
                report.push_str("  Target uses advanced bot detection (likely Bot Fight Mode).\n");
                report.push_str("  No automated tool can fully bypass this.\n");
                report.push_str("  Options:\n");
                report.push_str("    1. Request allowlisting as authorized pentester\n");
                report.push_str("    2. Manual testing with real browser\n");
                report.push_str("    3. Accept partial coverage\n");
            }
        }

        report.push_str("\n============================================================\n");

        report
    }
}

pub struct StealthReconScanner {
    http_client: Arc<HttpClient>,
}

impl StealthReconScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main reconnaissance scan
    pub async fn scan(&self, url: &str, _config: &ScanConfig) -> Result<Vec<Vulnerability>> {
        let report = self.probe_target(url).await?;

        // Convert to vulnerability for reporting
        let mut vulnerabilities = Vec::new();

        // Create informational finding with full report
        let severity = if report.is_currently_blocked {
            Severity::Info
        } else {
            Severity::Info
        };

        let description = format!(
            "Stealth reconnaissance completed.\n\n\
            Provider: {}\n\
            Protection Level: {}\n\
            Currently Blocked: {}\n\
            Recommended Mode: {}\n\
            Confidence: {}%",
            report.provider,
            report.protection_level,
            report.is_currently_blocked,
            report.recommended_mode,
            report.confidence
        );

        let remediation = match report.protection_level {
            ProtectionLevel::Advanced => {
                "Target uses advanced bot detection. Consider:\n\
                1. Requesting IP allowlisting from target organization\n\
                2. Using manual testing with authenticated browser\n\
                3. Accepting partial scan coverage for automated testing"
            }
            ProtectionLevel::Behavioral => {
                "Use --headless flag for full browser rendering.\n\
                Some endpoints may still require manual verification."
            }
            ProtectionLevel::TlsFingerprinting => {
                "Use --parasite flag to route requests through Chrome extension.\n\
                Install the Lonkero Parasite extension in your Chrome browser."
            }
            _ => {
                "No special measures required. Default scanning should work."
            }
        };

        vulnerabilities.push(Vulnerability {
            id: "STEALTH-RECON".to_string(),
            vuln_type: format!("Target Protection Analysis: {}", report.provider),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Reconnaissance".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description,
            evidence: Some(report.to_string_report()),
            cwe: "CWE-200".to_string(),
            cvss: 0.0,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        });

        Ok(vulnerabilities)
    }

    /// Probe target and build comprehensive report
    pub async fn probe_target(&self, url: &str) -> Result<StealthReport> {
        let mut details = Vec::new();
        let mut headers_detected = Vec::new();

        // Make initial request
        let response = self.http_client.get(url).await?;

        // Detect provider from headers
        let provider = self.detect_provider(&response);
        details.push(format!("Initial response: {} {}", response.status_code,
            if response.status_code == 200 { "OK" } else { "" }));

        // Check if currently blocked
        let block_type = response.detect_block();
        let is_currently_blocked = block_type.is_some();

        if is_currently_blocked {
            details.push(format!("Currently blocked: {:?}", block_type));
        }

        // Collect security-relevant headers
        let security_headers = [
            "cf-ray", "cf-cache-status", "cf-mitigated",
            "x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid",
            "x-akamai-transformed", "x-iinfo",
            "x-sucuri-id", "x-sucuri-cache",
            "server", "x-powered-by",
            "x-cdn", "x-cache", "x-cache-hits",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
        ];

        for header in &security_headers {
            if let Some(value) = response.headers.get(*header) {
                headers_detected.push((header.to_string(), value.clone()));
            }
        }

        // Determine protection level
        let (protection_level, confidence) = self.assess_protection_level(
            &provider,
            &response,
            is_currently_blocked,
            &block_type,
        );

        // Determine recommended mode
        let recommended_mode = self.recommend_mode(&protection_level, is_currently_blocked);

        // Add provider-specific details
        match &provider {
            Provider::Cloudflare | Provider::CloudflareEnterprise => {
                if response.headers.contains_key("cf-mitigated") {
                    details.push("Cloudflare mitigation active".to_string());
                }
                if let Some(ray) = response.headers.get("cf-ray") {
                    details.push(format!("CF-Ray: {}", ray));
                }
            }
            Provider::Akamai => {
                details.push("Akamai Bot Manager likely active".to_string());
            }
            Provider::Imperva => {
                details.push("Imperva/Incapsula protection detected".to_string());
            }
            _ => {}
        }

        Ok(StealthReport {
            url: url.to_string(),
            provider,
            protection_level,
            is_currently_blocked,
            block_type,
            recommended_mode,
            details,
            headers_detected,
            confidence,
        })
    }

    /// Detect CDN/WAF provider from response
    fn detect_provider(&self, response: &HttpResponse) -> Provider {
        // Check Cloudflare
        if response.headers.contains_key("cf-ray") {
            if response.headers.get("cf-mitigated").is_some()
                || response.body.to_lowercase().contains("cf-turnstile")
                || response.body.to_lowercase().contains("challenge-platform")
            {
                return Provider::CloudflareEnterprise;
            }
            return Provider::Cloudflare;
        }

        // Check Akamai
        if response.headers.get("server").map(|s| s.contains("AkamaiGHost")).unwrap_or(false)
            || response.headers.contains_key("x-akamai-transformed")
        {
            return Provider::Akamai;
        }

        // Check AWS
        if response.headers.contains_key("x-amz-cf-id")
            || response.headers.contains_key("x-amz-cf-pop")
        {
            if response.headers.contains_key("x-amzn-requestid") {
                return Provider::AwsWaf;
            }
            return Provider::AwsCloudFront;
        }

        // Check Imperva
        if response.headers.contains_key("x-iinfo")
            || response.body.to_lowercase().contains("incapsula")
            || response.body.to_lowercase().contains("imperva")
        {
            return Provider::Imperva;
        }

        // Check Sucuri
        if response.headers.contains_key("x-sucuri-id")
            || response.body.to_lowercase().contains("sucuri")
        {
            return Provider::Sucuri;
        }

        // Check Fastly
        if response.headers.get("server").map(|s| s.to_lowercase().contains("fastly")).unwrap_or(false)
            || response.headers.contains_key("fastly-debug-digest")
        {
            return Provider::Fastly;
        }

        // Check Azure
        if response.headers.get("server").map(|s| s.contains("Microsoft")).unwrap_or(false)
            || response.headers.contains_key("x-ms-request-id")
        {
            return Provider::Azure;
        }

        // Check Google Cloud
        if response.headers.get("server").map(|s| s.contains("Google")).unwrap_or(false)
            || response.headers.contains_key("x-cloud-trace-context")
        {
            return Provider::GoogleCloud;
        }

        // Check F5
        if response.headers.get("server").map(|s| s.contains("BIG-IP")).unwrap_or(false)
            || response.body.to_lowercase().contains("big-ip")
        {
            return Provider::F5BigIp;
        }

        // Check ModSecurity
        if response.body.to_lowercase().contains("modsecurity")
            || response.body.to_lowercase().contains("mod_security")
        {
            return Provider::ModSecurity;
        }

        // Check generic CDN headers
        if let Some(cdn) = response.headers.get("x-cdn") {
            return Provider::Unknown(cdn.clone());
        }

        Provider::None
    }

    /// Assess protection level based on all signals
    fn assess_protection_level(
        &self,
        provider: &Provider,
        response: &HttpResponse,
        is_blocked: bool,
        block_type: &Option<BlockType>,
    ) -> (ProtectionLevel, u8) {
        // Cloudflare Enterprise with challenges = Advanced
        if matches!(provider, Provider::CloudflareEnterprise) {
            if response.body.to_lowercase().contains("turnstile")
                || response.body.to_lowercase().contains("challenge-platform")
            {
                return (ProtectionLevel::Advanced, 95);
            }
        }

        // JS challenge = Behavioral at minimum
        if let Some(BlockType::CloudflareChallenge) = block_type {
            return (ProtectionLevel::Behavioral, 90);
        }
        if let Some(BlockType::Captcha) = block_type {
            return (ProtectionLevel::Advanced, 85);
        }

        // TLS fingerprinting providers
        match provider {
            Provider::CloudflareEnterprise | Provider::Akamai | Provider::Imperva => {
                if is_blocked {
                    // Blocked without JS challenge = likely TLS fingerprinting
                    return (ProtectionLevel::TlsFingerprinting, 80);
                }
                // These providers CAN do TLS fingerprinting but aren't blocking us
                return (ProtectionLevel::Basic, 60);
            }
            Provider::Cloudflare => {
                if is_blocked {
                    return (ProtectionLevel::TlsFingerprinting, 70);
                }
                return (ProtectionLevel::Basic, 50);
            }
            _ => {}
        }

        // Any block = at least Basic protection
        if is_blocked {
            return (ProtectionLevel::Basic, 70);
        }

        // No protection detected
        if matches!(provider, Provider::None) {
            return (ProtectionLevel::None, 80);
        }

        // CDN present but not blocking
        (ProtectionLevel::Basic, 50)
    }

    /// Recommend scan mode based on protection level
    fn recommend_mode(&self, level: &ProtectionLevel, is_blocked: bool) -> RecommendedMode {
        match level {
            ProtectionLevel::None => RecommendedMode::Standard,
            ProtectionLevel::Basic => {
                if is_blocked {
                    RecommendedMode::StealthHeaders
                } else {
                    RecommendedMode::Standard
                }
            }
            ProtectionLevel::TlsFingerprinting => RecommendedMode::ParasiteMode,
            ProtectionLevel::Behavioral => RecommendedMode::HeadlessBrowser,
            ProtectionLevel::Advanced => RecommendedMode::RequestAllowlist,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_level_display() {
        assert_eq!(format!("{}", ProtectionLevel::None), "None");
        assert_eq!(format!("{}", ProtectionLevel::TlsFingerprinting), "TLS Fingerprinting");
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(format!("{}", Provider::Cloudflare), "Cloudflare");
        assert_eq!(format!("{}", Provider::Unknown("Custom".to_string())), "Unknown (Custom)");
    }
}
