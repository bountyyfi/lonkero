// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - OpenID Connect (OIDC) Security Scanner
 * Comprehensive testing for OIDC vulnerabilities and misconfigurations
 *
 * Tests for:
 * - Discovery & configuration issues
 * - ID Token vulnerabilities (algorithm confusion, signature bypass)
 * - Authorization code flow issues
 * - Token endpoint security
 * - Scope & claims exposure
 * - Session management issues
 * - Provider confusion attacks
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::analysis::{AuthType, IntelligenceBus};
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// OIDC Identity Provider types
#[derive(Debug, Clone, PartialEq, Default)]
pub enum OidcProvider {
    Okta,
    Auth0,
    AzureAd,
    Keycloak,
    Cognito,
    Google,
    PingIdentity,
    OneLogin,
    Generic,
    #[default]
    Unknown,
}

impl OidcProvider {
    fn from_issuer(issuer: &str) -> Self {
        let issuer_lower = issuer.to_lowercase();
        if issuer_lower.contains("okta.com") || issuer_lower.contains("oktapreview") {
            OidcProvider::Okta
        } else if issuer_lower.contains("auth0.com") {
            OidcProvider::Auth0
        } else if issuer_lower.contains("login.microsoftonline.com")
            || issuer_lower.contains("sts.windows.net")
        {
            OidcProvider::AzureAd
        } else if issuer_lower.contains("keycloak") {
            OidcProvider::Keycloak
        } else if issuer_lower.contains("cognito") || issuer_lower.contains("amazoncognito") {
            OidcProvider::Cognito
        } else if issuer_lower.contains("accounts.google.com") {
            OidcProvider::Google
        } else if issuer_lower.contains("pingidentity") || issuer_lower.contains("pingone") {
            OidcProvider::PingIdentity
        } else if issuer_lower.contains("onelogin") {
            OidcProvider::OneLogin
        } else {
            OidcProvider::Generic
        }
    }

    fn get_remediation_docs(&self) -> &'static str {
        match self {
            OidcProvider::Okta => "https://developer.okta.com/docs/reference/api/oidc/",
            OidcProvider::Auth0 => "https://auth0.com/docs/authenticate/protocols/openid-connect-protocol",
            OidcProvider::AzureAd => "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc",
            OidcProvider::Keycloak => "https://www.keycloak.org/docs/latest/securing_apps/",
            OidcProvider::Cognito => "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html",
            OidcProvider::Google => "https://developers.google.com/identity/openid-connect/openid-connect",
            OidcProvider::PingIdentity => "https://docs.pingidentity.com/",
            OidcProvider::OneLogin => "https://developers.onelogin.com/openid-connect",
            _ => "https://openid.net/specs/openid-connect-core-1_0.html",
        }
    }
}

/// OIDC Discovery configuration parsed from .well-known endpoint
#[derive(Debug, Clone, Default)]
pub struct OidcConfiguration {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub frontchannel_logout_supported: bool,
    pub backchannel_logout_supported: bool,
    pub provider: OidcProvider,
    pub raw_config: String,
}

impl OidcConfiguration {
    fn from_json(json_str: &str) -> Option<Self> {
        let json: serde_json::Value = serde_json::from_str(json_str).ok()?;

        let mut config = Self::default();
        config.raw_config = json_str.to_string();

        config.issuer = json
            .get("issuer")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.authorization_endpoint = json
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.token_endpoint = json
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.userinfo_endpoint = json
            .get("userinfo_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.jwks_uri = json
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.end_session_endpoint = json
            .get("end_session_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.revocation_endpoint = json
            .get("revocation_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        config.introspection_endpoint = json
            .get("introspection_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from);

        config.response_types_supported =
            Self::extract_string_array(&json, "response_types_supported");
        config.response_modes_supported =
            Self::extract_string_array(&json, "response_modes_supported");
        config.grant_types_supported = Self::extract_string_array(&json, "grant_types_supported");
        config.subject_types_supported =
            Self::extract_string_array(&json, "subject_types_supported");
        config.id_token_signing_alg_values_supported =
            Self::extract_string_array(&json, "id_token_signing_alg_values_supported");
        config.scopes_supported = Self::extract_string_array(&json, "scopes_supported");
        config.claims_supported = Self::extract_string_array(&json, "claims_supported");
        config.token_endpoint_auth_methods_supported =
            Self::extract_string_array(&json, "token_endpoint_auth_methods_supported");
        config.code_challenge_methods_supported =
            Self::extract_string_array(&json, "code_challenge_methods_supported");

        config.frontchannel_logout_supported = json
            .get("frontchannel_logout_supported")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        config.backchannel_logout_supported = json
            .get("backchannel_logout_supported")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if let Some(issuer) = &config.issuer {
            config.provider = OidcProvider::from_issuer(issuer);
        }

        Some(config)
    }

    fn extract_string_array(json: &serde_json::Value, key: &str) -> Vec<String> {
        json.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// OIDC Detection result
#[derive(Debug)]
struct OidcDetection {
    has_oidc: bool,
    oidc_endpoints: Vec<String>,
    discovery_url: Option<String>,
    configuration: Option<OidcConfiguration>,
    evidence: Vec<String>,
}

pub struct OidcScanner {
    http_client: Arc<HttpClient>,
    intelligence_bus: Option<Arc<IntelligenceBus>>,
}

impl OidcScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            intelligence_bus: None,
        }
    }

    /// Configure the scanner with an intelligence bus for cross-scanner communication
    pub fn with_intelligence(mut self, bus: Arc<IntelligenceBus>) -> Self {
        self.intelligence_bus = Some(bus);
        self
    }

    /// Broadcast OIDC authentication detected
    async fn broadcast_oidc_detected(&self, url: &str, confidence: f32) {
        if let Some(ref bus) = self.intelligence_bus {
            bus.report_auth_type(AuthType::OIDC, confidence, url).await;
        }
    }

    /// Scan URL for OIDC vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[OIDC] Scanning: {}", url);

        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        if !crate::license::verify_rt_state() {
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, check application characteristics
        tests_run += 1;
        let baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[OIDC] Could not fetch URL: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        // Skip if no OAuth/OIDC indicators detected
        if characteristics.should_skip_oauth_tests()
            && !self.has_oidc_indicators(&baseline_response, url)
        {
            info!("[OIDC] No OIDC implementation detected - skipping OIDC tests");
            return Ok((vulnerabilities, tests_run));
        }

        // Detect OIDC implementation
        tests_run += 1;
        let detection = self.detect_oidc_implementation(url).await;

        if !detection.has_oidc {
            info!("[OIDC] No OIDC implementation detected on closer inspection");
            return Ok((vulnerabilities, tests_run));
        }

        info!(
            "[OIDC] OIDC implementation detected: {:?}",
            detection.evidence
        );

        // Broadcast OIDC detection to Intelligence Bus
        // Higher confidence if we have a valid discovery configuration
        let confidence = if detection.configuration.is_some() {
            0.95
        } else if detection.discovery_url.is_some() {
            0.85
        } else {
            0.70
        };
        self.broadcast_oidc_detected(url, confidence).await;

        // If we have a configuration, run comprehensive tests
        if let Some(ref config) = detection.configuration {
            info!("[OIDC] Provider detected: {:?}", config.provider);

            // Test 1: Configuration security analysis
            tests_run += 1;
            self.check_configuration_security(config, url, &mut vulnerabilities);

            // Test 2: Check insecure algorithms
            tests_run += 1;
            self.check_insecure_algorithms(config, url, &mut vulnerabilities);

            // Test 3: Check for missing PKCE support
            tests_run += 1;
            self.check_pkce_support(config, url, &mut vulnerabilities);

            // Test 4: Check implicit flow risks
            tests_run += 1;
            self.check_implicit_flow_risks(config, url, &mut vulnerabilities);

            // Test 5: Check scope exposure
            tests_run += 1;
            self.check_scope_exposure(config, url, &mut vulnerabilities);

            // Test 6: Check claims exposure
            tests_run += 1;
            self.check_sensitive_claims(config, url, &mut vulnerabilities);

            // Test 7: Check logout implementation
            tests_run += 1;
            self.check_logout_implementation(config, url, &mut vulnerabilities);

            // Test 8: Check token endpoint auth methods
            tests_run += 1;
            self.check_token_endpoint_auth(config, url, &mut vulnerabilities);
        }

        // Test 9: Check for ID token in URL
        tests_run += 1;
        self.check_id_token_in_url(url, &mut vulnerabilities);

        // Test 10: Test nonce validation
        tests_run += 1;
        if let Some(ref config) = detection.configuration {
            if let Err(e) = self
                .test_nonce_validation(config, url, &mut vulnerabilities)
                .await
            {
                debug!("[OIDC] Nonce validation test error: {}", e);
            }
        }

        // Test 11: Test issuer validation
        tests_run += 1;
        if let Some(ref config) = detection.configuration {
            if let Err(e) = self
                .test_issuer_validation(config, url, &mut vulnerabilities)
                .await
            {
                debug!("[OIDC] Issuer validation test error: {}", e);
            }
        }

        // Test 12: Check for algorithm confusion vulnerability indicators
        tests_run += 1;
        if let Some(ref config) = detection.configuration {
            self.check_algorithm_confusion_risk(config, url, &mut vulnerabilities);
        }

        // Test 13: Check authorization code flow security
        tests_run += 1;
        if let Some(ref config) = detection.configuration {
            if let Err(e) = self
                .test_authorization_code_security(config, url, &mut vulnerabilities)
                .await
            {
                debug!("[OIDC] Auth code security test error: {}", e);
            }
        }

        // Test 14: Check for provider confusion risks
        tests_run += 1;
        self.check_provider_confusion(&baseline_response, url, &mut vulnerabilities);

        // Test 15: Check client secret exposure
        tests_run += 1;
        self.check_client_secret_exposure(&baseline_response, url, &mut vulnerabilities);

        // Test 16: Test userinfo endpoint security
        tests_run += 1;
        if let Some(ref config) = detection.configuration {
            if let Err(e) = self
                .test_userinfo_endpoint(config, url, &mut vulnerabilities)
                .await
            {
                debug!("[OIDC] UserInfo endpoint test error: {}", e);
            }
        }

        // Deduplicate vulnerabilities
        let mut seen_types = HashSet::new();
        let unique_vulns: Vec<Vulnerability> = vulnerabilities
            .into_iter()
            .filter(|v| {
                let key = format!("{}:{}", v.vuln_type, v.url);
                seen_types.insert(key)
            })
            .collect();

        info!(
            "[SUCCESS] [OIDC] Completed {} tests, found {} unique issues",
            tests_run,
            unique_vulns.len()
        );

        Ok((unique_vulns, tests_run))
    }

    /// Check for OIDC indicators in response
    fn has_oidc_indicators(&self, response: &HttpResponse, url: &str) -> bool {
        let body_lower = response.body.to_lowercase();
        let url_lower = url.to_lowercase();

        // URL indicators
        if url_lower.contains("openid")
            || url_lower.contains("oidc")
            || url_lower.contains("/.well-known/openid-configuration")
            || url_lower.contains("id_token")
        {
            return true;
        }

        // Body indicators
        body_lower.contains("openid")
            || body_lower.contains("id_token")
            || body_lower.contains("openid-configuration")
            || body_lower.contains("\"iss\"")
            || body_lower.contains("\"sub\"")
            || body_lower.contains("scope=openid")
    }

    /// Detect OIDC implementation
    async fn detect_oidc_implementation(&self, url: &str) -> OidcDetection {
        let mut detection = OidcDetection {
            has_oidc: false,
            oidc_endpoints: Vec::new(),
            discovery_url: None,
            configuration: None,
            evidence: Vec::new(),
        };

        // Extract base URL
        let base_url = self.extract_base_url(url);

        // Try common OIDC discovery endpoints
        let discovery_endpoints = vec![
            format!("{}/.well-known/openid-configuration", base_url),
            format!("{}/oauth2/.well-known/openid-configuration", base_url),
            format!("{}/.well-known/oauth-authorization-server", base_url),
            format!(
                "{}/realms/master/.well-known/openid-configuration",
                base_url
            ), // Keycloak
            format!("{}/.well-known/openid-configuration/", base_url), // Trailing slash variant
        ];

        for endpoint in &discovery_endpoints {
            if let Ok(response) = self.http_client.get(endpoint).await {
                if response.status_code == 200 && response.body.contains("\"issuer\"") {
                    detection.has_oidc = true;
                    detection.discovery_url = Some(endpoint.clone());
                    detection
                        .evidence
                        .push(format!("Discovery endpoint: {}", endpoint));

                    if let Some(config) = OidcConfiguration::from_json(&response.body) {
                        detection.configuration = Some(config);
                    }
                    break;
                }
            }
        }

        // Check URL for OIDC parameters
        let url_lower = url.to_lowercase();
        if url_lower.contains("scope=openid") || url_lower.contains("id_token") {
            detection.has_oidc = true;
            detection
                .evidence
                .push("OIDC parameters in URL".to_string());
        }

        // Check response for OIDC indicators
        if let Ok(response) = self.http_client.get(url).await {
            let body_lower = response.body.to_lowercase();

            let oidc_patterns = [
                "openid-connect",
                "id_token",
                "nonce=",
                "scope=openid",
                "/.well-known/openid-configuration",
            ];

            for pattern in &oidc_patterns {
                if body_lower.contains(pattern) {
                    detection.has_oidc = true;
                    detection
                        .evidence
                        .push(format!("Pattern found: {}", pattern));
                }
            }
        }

        detection
    }

    /// Extract base URL from full URL
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.split('/').take(3).collect::<Vec<_>>().join("/")
        }
    }

    /// Check configuration security
    fn check_configuration_security(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check for missing required endpoints
        if config.token_endpoint.is_none() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Missing Token Endpoint",
                url,
                Severity::Medium,
                Confidence::High,
                "OIDC discovery document missing token_endpoint - may indicate misconfiguration",
                "token_endpoint not found in discovery document".to_string(),
                5.0,
                "CWE-16",
                &config.provider,
            ));
        }

        if config.jwks_uri.is_none() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Missing JWKS URI",
                url,
                Severity::High,
                Confidence::High,
                "OIDC discovery document missing jwks_uri - token signature verification may be impossible",
                "jwks_uri not found in discovery document".to_string(),
                7.5,
                "CWE-345",
                &config.provider,
            ));
        }

        // Check for HTTP (non-HTTPS) endpoints
        let endpoints_to_check = [
            (&config.authorization_endpoint, "authorization_endpoint"),
            (&config.token_endpoint, "token_endpoint"),
            (&config.userinfo_endpoint, "userinfo_endpoint"),
        ];

        for (endpoint, name) in &endpoints_to_check {
            if let Some(ep) = endpoint {
                if ep.starts_with("http://")
                    && !ep.contains("localhost")
                    && !ep.contains("127.0.0.1")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "OIDC Endpoint Using HTTP",
                        url,
                        Severity::Critical,
                        Confidence::High,
                        &format!(
                            "OIDC {} uses insecure HTTP - tokens can be intercepted",
                            name
                        ),
                        format!("{}: {}", name, ep),
                        9.0,
                        "CWE-319",
                        &config.provider,
                    ));
                }
            }
        }
    }

    /// Check for insecure signing algorithms
    fn check_insecure_algorithms(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let algorithms = &config.id_token_signing_alg_values_supported;

        // Check for 'none' algorithm
        if algorithms.iter().any(|a| a.to_lowercase() == "none") {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC None Algorithm Supported",
                url,
                Severity::Critical,
                Confidence::High,
                "OIDC provider supports 'none' algorithm - allows unsigned token forgery",
                "id_token_signing_alg_values_supported includes 'none'".to_string(),
                9.8,
                "CWE-327",
                &config.provider,
            ));
        }

        // Check for weak algorithms (HS256 with public keys can be vulnerable)
        let weak_algs: Vec<&String> = algorithms
            .iter()
            .filter(|a| {
                let lower = a.to_lowercase();
                lower == "hs256" || lower == "hs384" || lower == "hs512"
            })
            .collect();

        let asymmetric_algs: Vec<&String> = algorithms
            .iter()
            .filter(|a| {
                let lower = a.to_lowercase();
                lower.starts_with("rs") || lower.starts_with("es") || lower.starts_with("ps")
            })
            .collect();

        // If both symmetric and asymmetric algorithms are supported, algorithm confusion is possible
        if !weak_algs.is_empty() && !asymmetric_algs.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Algorithm Confusion Risk",
                url,
                Severity::High,
                Confidence::Medium,
                "OIDC provider supports both symmetric (HS*) and asymmetric (RS*/ES*) algorithms - algorithm confusion attack possible if public key is available",
                format!("Symmetric: {:?}, Asymmetric: {:?}", weak_algs, asymmetric_algs),
                7.5,
                "CWE-327",
                &config.provider,
            ));
        }

        // Check for deprecated algorithms
        let deprecated_algs: Vec<&str> = algorithms
            .iter()
            .filter(|a| {
                let lower = a.to_lowercase();
                lower == "rs256" || lower == "ps256" // SHA-256 still ok, but check for SHA-1
            })
            .map(|s| s.as_str())
            .collect();

        // SHA-1 based algorithms (unlikely but check)
        if algorithms.iter().any(|a| a.to_lowercase().contains("sha1")) {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC SHA-1 Algorithm Detected",
                url,
                Severity::Medium,
                Confidence::High,
                "OIDC provider uses SHA-1 based algorithm - considered cryptographically weak",
                "SHA-1 based algorithm in id_token_signing_alg_values_supported".to_string(),
                5.9,
                "CWE-328",
                &config.provider,
            ));
        }
    }

    /// Check for missing PKCE support
    fn check_pkce_support(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let pkce_methods = &config.code_challenge_methods_supported;

        if pkce_methods.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Missing PKCE Support",
                url,
                Severity::Medium,
                Confidence::Medium,
                "OIDC provider does not advertise PKCE support - authorization code interception possible for public clients",
                "code_challenge_methods_supported not found or empty".to_string(),
                6.0,
                "CWE-287",
                &config.provider,
            ));
        } else if !pkce_methods.iter().any(|m| m == "S256") {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Weak PKCE Method",
                url,
                Severity::Low,
                Confidence::Medium,
                "OIDC provider does not support S256 PKCE method - 'plain' method is weaker",
                format!("Supported methods: {:?}", pkce_methods),
                4.0,
                "CWE-287",
                &config.provider,
            ));
        }
    }

    /// Check for implicit flow risks
    fn check_implicit_flow_risks(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let response_types = &config.response_types_supported;

        // Check for implicit flow (token in URL fragment)
        let has_implicit = response_types.iter().any(|rt| {
            let lower = rt.to_lowercase();
            lower == "token" || lower == "id_token token" || lower == "token id_token"
        });

        if has_implicit {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Implicit Flow Enabled",
                url,
                Severity::Medium,
                Confidence::High,
                "OIDC provider supports implicit flow - tokens exposed in URL fragment, vulnerable to history/referrer leakage",
                format!("response_types_supported includes implicit flow: {:?}", response_types),
                6.5,
                "CWE-598",
                &config.provider,
            ));
        }

        // Check for id_token only (hybrid variant)
        let has_id_token_only = response_types.iter().any(|rt| rt == "id_token");
        if has_id_token_only {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC ID Token Direct Response",
                url,
                Severity::Low,
                Confidence::Medium,
                "OIDC provider supports id_token response type - ensure nonce validation is enforced",
                "response_types_supported includes 'id_token'".to_string(),
                4.0,
                "CWE-290",
                &config.provider,
            ));
        }
    }

    /// Check for scope exposure
    fn check_scope_exposure(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let scopes = &config.scopes_supported;

        // Check for sensitive scopes
        let sensitive_scopes: Vec<&String> = scopes
            .iter()
            .filter(|s| {
                let lower = s.to_lowercase();
                lower.contains("admin")
                    || lower.contains("write")
                    || lower.contains("delete")
                    || lower.contains("full")
                    || lower.contains("all")
            })
            .collect();

        if !sensitive_scopes.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Sensitive Scopes Available",
                url,
                Severity::Info,
                Confidence::Low,
                "OIDC provider exposes potentially sensitive scopes - review scope requirements",
                format!("Sensitive scopes found: {:?}", sensitive_scopes),
                3.0,
                "CWE-285",
                &config.provider,
            ));
        }

        // Check for offline_access scope (long-lived tokens)
        if scopes.iter().any(|s| s == "offline_access") {
            debug!("[OIDC] offline_access scope available - refresh tokens enabled");
        }
    }

    /// Check for sensitive claims exposure
    fn check_sensitive_claims(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let claims = &config.claims_supported;

        // Sensitive claims that might expose PII
        let sensitive_claims: Vec<&String> = claims
            .iter()
            .filter(|c| {
                let lower = c.to_lowercase();
                lower.contains("phone")
                    || lower.contains("address")
                    || lower.contains("birthdate")
                    || lower.contains("gender")
                    || lower.contains("ssn")
                    || lower.contains("national")
                    || lower.contains("passport")
                    || lower.contains("license")
            })
            .collect();

        if !sensitive_claims.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Sensitive Claims Available",
                url,
                Severity::Low,
                Confidence::Medium,
                "OIDC provider can expose sensitive PII claims - ensure proper consent and minimum necessary data",
                format!("Sensitive claims: {:?}", sensitive_claims),
                4.0,
                "CWE-359",
                &config.provider,
            ));
        }
    }

    /// Check logout implementation
    fn check_logout_implementation(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check for missing logout endpoints
        if config.end_session_endpoint.is_none() {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Missing Logout Endpoint",
                url,
                Severity::Medium,
                Confidence::Medium,
                "OIDC provider does not expose end_session_endpoint - proper logout may not be implemented",
                "end_session_endpoint not found in discovery".to_string(),
                5.5,
                "CWE-613",
                &config.provider,
            ));
        }

        // Check for missing logout channels
        if !config.frontchannel_logout_supported && !config.backchannel_logout_supported {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Missing Logout Channel Support",
                url,
                Severity::Low,
                Confidence::Medium,
                "OIDC provider does not support front-channel or back-channel logout - federated logout may not work properly",
                "Neither frontchannel_logout_supported nor backchannel_logout_supported is true".to_string(),
                4.0,
                "CWE-613",
                &config.provider,
            ));
        }
    }

    /// Check token endpoint authentication methods
    fn check_token_endpoint_auth(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let auth_methods = &config.token_endpoint_auth_methods_supported;

        // Check for client_secret_post (less secure than basic)
        if auth_methods.iter().any(|m| m == "client_secret_post")
            && !auth_methods
                .iter()
                .any(|m| m == "private_key_jwt" || m == "client_secret_jwt")
        {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Weak Token Endpoint Auth",
                url,
                Severity::Low,
                Confidence::Medium,
                "OIDC provider supports client_secret_post but not JWT-based authentication - consider using private_key_jwt for better security",
                format!("Supported methods: {:?}", auth_methods),
                3.5,
                "CWE-287",
                &config.provider,
            ));
        }

        // Check for none (public client only)
        if auth_methods.iter().any(|m| m == "none") {
            debug!("[OIDC] Token endpoint allows unauthenticated access (public clients)");
        }
    }

    /// Check for ID token in URL
    fn check_id_token_in_url(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        if url.contains("id_token=") {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC ID Token in URL",
                url,
                Severity::High,
                Confidence::High,
                "ID token exposed in URL - vulnerable to referrer leakage, browser history, and logging",
                "URL contains 'id_token=' parameter".to_string(),
                7.5,
                "CWE-598",
                &OidcProvider::Unknown,
            ));
        }
    }

    /// Test nonce validation
    async fn test_nonce_validation(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> Result<()> {
        // If we have an authorization endpoint, check if nonce is enforced
        if let Some(auth_endpoint) = &config.authorization_endpoint {
            // Test request without nonce for id_token response type
            let test_url = format!(
                "{}?response_type=id_token&client_id=test&redirect_uri={}&scope=openid",
                auth_endpoint,
                urlencoding::encode(url)
            );

            if let Ok(response) = self.http_client.get(&test_url).await {
                let body_lower = response.body.to_lowercase();

                // If no error about missing nonce, it might be optional
                if response.status_code != 400
                    && !body_lower.contains("nonce")
                    && !body_lower.contains("required")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "OIDC Nonce Not Enforced",
                        url,
                        Severity::Medium,
                        Confidence::Low,
                        "OIDC provider may not enforce nonce parameter for implicit/hybrid flows - replay attacks possible",
                        "Authorization request without nonce did not return error".to_string(),
                        5.5,
                        "CWE-290",
                        &config.provider,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Test issuer validation
    async fn test_issuer_validation(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> Result<()> {
        // Check if issuer matches discovery URL
        if let Some(issuer) = &config.issuer {
            let base_url = self.extract_base_url(url);

            if !issuer.starts_with(&base_url)
                && !base_url.contains(issuer.split('/').nth(2).unwrap_or(""))
            {
                vulnerabilities.push(self.create_vulnerability(
                    "OIDC Issuer Mismatch",
                    url,
                    Severity::Medium,
                    Confidence::Medium,
                    "OIDC issuer in discovery document does not match the discovery URL - verify issuer configuration",
                    format!("Issuer: {}, Discovery URL base: {}", issuer, base_url),
                    5.0,
                    "CWE-290",
                    &config.provider,
                ));
            }
        }

        Ok(())
    }

    /// Check for algorithm confusion attack indicators
    fn check_algorithm_confusion_risk(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If JWKS URI is available and both HS and RS algorithms are supported
        let has_hs = config
            .id_token_signing_alg_values_supported
            .iter()
            .any(|a| a.starts_with("HS"));
        let has_rs = config
            .id_token_signing_alg_values_supported
            .iter()
            .any(|a| a.starts_with("RS") || a.starts_with("ES") || a.starts_with("PS"));

        if config.jwks_uri.is_some() && has_hs && has_rs {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Algorithm Confusion Vulnerability Risk",
                url,
                Severity::High,
                Confidence::Medium,
                "OIDC provider has public JWKS and supports both symmetric and asymmetric algorithms - algorithm confusion attack may be possible if server doesn't validate algorithm claim",
                format!("JWKS URI: {:?}, Algorithms: {:?}", config.jwks_uri, config.id_token_signing_alg_values_supported),
                7.5,
                "CWE-345",
                &config.provider,
            ));
        }
    }

    /// Test authorization code flow security
    async fn test_authorization_code_security(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> Result<()> {
        if let Some(auth_endpoint) = &config.authorization_endpoint {
            // Test for state parameter enforcement
            let test_url = format!(
                "{}?response_type=code&client_id=test&redirect_uri={}&scope=openid",
                auth_endpoint,
                urlencoding::encode(url)
            );

            if let Ok(response) = self.http_client.get(&test_url).await {
                let body_lower = response.body.to_lowercase();

                // Check if state is required
                if response.status_code != 400
                    && !body_lower.contains("state")
                    && !body_lower.contains("required")
                    && !body_lower.contains("missing")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "OIDC State Parameter Not Enforced",
                        url,
                        Severity::Medium,
                        Confidence::Low,
                        "OIDC authorization endpoint may not enforce state parameter - CSRF attacks possible",
                        "Authorization request without state did not return error".to_string(),
                        5.9,
                        "CWE-352",
                        &config.provider,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Check for provider confusion attacks
    fn check_provider_confusion(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for multiple IdP configurations
        let idp_count = [
            "okta.com",
            "auth0.com",
            "login.microsoftonline",
            "cognito",
            "accounts.google.com",
            "keycloak",
        ]
        .iter()
        .filter(|idp| body_lower.contains(*idp))
        .count();

        if idp_count > 1 {
            vulnerabilities.push(self.create_vulnerability(
                "OIDC Multiple IdP Detection",
                url,
                Severity::Info,
                Confidence::Medium,
                "Multiple OIDC identity providers detected - ensure proper issuer validation to prevent IdP confusion attacks",
                format!("Multiple IdP references found in response ({} providers)", idp_count),
                3.0,
                "CWE-290",
                &OidcProvider::Generic,
            ));
        }

        // Check for mixed OAuth/OIDC flows
        if (body_lower.contains("oauth") || body_lower.contains("oauth2"))
            && body_lower.contains("openid")
        {
            // This is normal, but check for inconsistent configurations
            if body_lower.contains("response_type=token") && body_lower.contains("scope=openid") {
                debug!("[OIDC] Mixed OAuth/OIDC implicit flow detected");
            }
        }
    }

    /// Check for client secret exposure
    fn check_client_secret_exposure(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for client_secret in response
        if (body_lower.contains("client_secret") || body_lower.contains("clientsecret"))
            && (body.contains("=") || body.contains(":") || body.contains("\""))
        {
            // Additional check to avoid false positives on documentation
            if !body_lower.contains("example")
                && !body_lower.contains("documentation")
                && !body_lower.contains("tutorial")
                && !body_lower.contains("placeholder")
            {
                vulnerabilities.push(self.create_vulnerability(
                    "OIDC Client Secret Exposed",
                    url,
                    Severity::Critical,
                    Confidence::Medium,
                    "OIDC client_secret may be exposed in client-side code - enables token theft and impersonation",
                    "client_secret reference found in response body".to_string(),
                    9.5,
                    "CWE-798",
                    &OidcProvider::Unknown,
                ));
            }
        }
    }

    /// Test userinfo endpoint security
    async fn test_userinfo_endpoint(
        &self,
        config: &OidcConfiguration,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> Result<()> {
        if let Some(userinfo_endpoint) = &config.userinfo_endpoint {
            // Try accessing userinfo without token
            if let Ok(response) = self.http_client.get(userinfo_endpoint).await {
                if response.status_code == 200 && response.body.contains("\"sub\"") {
                    vulnerabilities.push(self.create_vulnerability(
                        "OIDC UserInfo Endpoint Unprotected",
                        url,
                        Severity::Critical,
                        Confidence::High,
                        "OIDC userinfo endpoint accessible without authentication - user data exposed",
                        format!("Endpoint {} returned user data without token", userinfo_endpoint),
                        9.1,
                        "CWE-306",
                        &config.provider,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
        cwe: &str,
        provider: &OidcProvider,
    ) -> Vulnerability {
        let remediation = self.get_remediation(title, provider);

        Vulnerability {
            id: format!("oidc_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("OpenID Connect - {}", title),
            severity,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Get remediation advice based on vulnerability and provider
    fn get_remediation(&self, vuln_type: &str, provider: &OidcProvider) -> String {
        let provider_docs = provider.get_remediation_docs();

        let base_remediation = match vuln_type {
            "OIDC None Algorithm Supported" => {
                r#"CRITICAL: Disable 'none' algorithm immediately.

1. **Remove 'none' from supported algorithms**
   Configure your IdP to only allow secure signing algorithms:
   - RS256, RS384, RS512 (RSA + SHA-2)
   - ES256, ES384, ES512 (ECDSA)
   - PS256, PS384, PS512 (RSA-PSS)

2. **Always validate algorithm claim**
   ```javascript
   // Verify the token uses an expected algorithm
   const allowedAlgorithms = ['RS256', 'ES256'];
   if (!allowedAlgorithms.includes(header.alg)) {
     throw new Error('Invalid algorithm');
   }
   ```

3. **Reject tokens without signatures**"#
            }

            "OIDC Algorithm Confusion Risk" | "OIDC Algorithm Confusion Vulnerability Risk" => {
                r#"HIGH: Prevent algorithm confusion attacks.

1. **Use asymmetric algorithms only**
   Remove HS256/HS384/HS512 from supported algorithms if using public keys.

2. **Validate algorithm matches expected type**
   ```python
   # Python example
   def verify_token(token, public_key):
       header = jwt.get_unverified_header(token)
       if header['alg'] not in ['RS256', 'ES256']:
           raise ValueError('Unexpected algorithm')
       return jwt.decode(token, public_key, algorithms=['RS256', 'ES256'])
   ```

3. **Never use the public key as a symmetric secret**

4. **Configure strict algorithm validation in your JWT library**"#
            }

            "OIDC Missing PKCE Support" => {
                r#"MEDIUM: Implement PKCE for authorization code flow.

1. **Enable PKCE in your OIDC provider**
   - Most modern IdPs support PKCE by default
   - Require PKCE for public clients (SPAs, mobile apps)

2. **Client implementation**
   ```javascript
   // Generate PKCE parameters
   const codeVerifier = generateRandomString(64);
   const codeChallenge = base64UrlEncode(sha256(codeVerifier));

   // Authorization request
   const authUrl = `${authEndpoint}?` +
     `code_challenge=${codeChallenge}&` +
     `code_challenge_method=S256&...`;

   // Token request includes verifier
   const tokenResponse = await fetch(tokenEndpoint, {
     method: 'POST',
     body: new URLSearchParams({
       code: authCode,
       code_verifier: codeVerifier,
       grant_type: 'authorization_code'
     })
   });
   ```

3. **Use S256 method (not plain)**"#
            }

            "OIDC Implicit Flow Enabled" => {
                r#"MEDIUM: Migrate from implicit flow to authorization code flow with PKCE.

1. **Deprecate implicit flow**
   Remove 'token' and 'id_token token' from response_types_supported.

2. **Use authorization code flow**
   ```javascript
   // Use response_type=code instead of response_type=token
   const authUrl = `${authEndpoint}?` +
     `response_type=code&` +
     `code_challenge=${codeChallenge}&...`;
   ```

3. **Implement PKCE for SPAs and mobile apps**

4. **Enable refresh token rotation**"#
            }

            "OIDC Missing Logout Endpoint" => {
                r#"MEDIUM: Implement proper logout functionality.

1. **Configure end_session_endpoint in your IdP**

2. **Implement RP-initiated logout**
   ```javascript
   // Redirect to end_session_endpoint
   const logoutUrl = `${endSessionEndpoint}?` +
     `id_token_hint=${idToken}&` +
     `post_logout_redirect_uri=${redirectUri}`;
   window.location.href = logoutUrl;
   ```

3. **Clear local session on logout**

4. **Consider implementing back-channel logout for federated scenarios**"#
            }

            "OIDC Client Secret Exposed" => {
                r#"CRITICAL: Remove client secret from client-side code immediately.

1. **Never include client_secret in frontend code**

2. **Use PKCE for public clients**
   Public clients (SPAs, mobile apps) should use PKCE instead of client secrets.

3. **Implement a backend proxy**
   ```javascript
   // Frontend calls your backend
   const tokenResponse = await fetch('/api/auth/token', {
     method: 'POST',
     body: JSON.stringify({ code: authCode })
   });

   // Backend (server-side) handles client_secret
   ```

4. **Rotate compromised secrets immediately**

5. **Consider using private_key_jwt authentication**"#
            }

            "OIDC Nonce Not Enforced" => {
                r#"MEDIUM: Enforce nonce validation for implicit/hybrid flows.

1. **Generate cryptographically random nonce**
   ```javascript
   const nonce = crypto.randomUUID();
   sessionStorage.setItem('oidc_nonce', nonce);

   const authUrl = `${authEndpoint}?` +
     `response_type=id_token&` +
     `nonce=${nonce}&...`;
   ```

2. **Validate nonce in received token**
   ```javascript
   const tokenNonce = decodedToken.nonce;
   const storedNonce = sessionStorage.getItem('oidc_nonce');
   if (tokenNonce !== storedNonce) {
     throw new Error('Nonce mismatch - possible replay attack');
   }
   ```

3. **Configure IdP to require nonce for implicit flows**"#
            }

            "OIDC UserInfo Endpoint Unprotected" => {
                r#"CRITICAL: Protect userinfo endpoint with access token validation.

1. **Require valid access token**
   ```
   GET /userinfo
   Authorization: Bearer <access_token>
   ```

2. **Validate token before returning user data**

3. **Implement proper token introspection if needed**

4. **Review IdP access token validation settings**"#
            }

            _ => {
                r#"General OIDC Security Recommendations:

1. **Use authorization code flow with PKCE**
2. **Validate all tokens thoroughly (issuer, audience, expiry, signature)**
3. **Implement proper state and nonce validation**
4. **Use secure, random values for security parameters**
5. **Prefer asymmetric signing algorithms (RS256, ES256)**
6. **Implement proper logout functionality**
7. **Store tokens securely (HttpOnly cookies or encrypted storage)**
8. **Implement token rotation for refresh tokens**
9. **Monitor for suspicious token usage patterns**"#
            }
        };

        format!(
            "{}\n\nProvider-specific documentation: {}

References:
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            base_remediation,
            provider_docs
        )
    }
}

// UUID generation helper
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> UuidValue {
            UuidValue
        }
    }

    pub struct UuidValue;

    impl UuidValue {
        pub fn to_string(&self) -> String {
            use rand::Rng;
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_mock_http_client() -> Arc<HttpClient> {
        Arc::new(HttpClient::new(5, 2).unwrap())
    }

    #[test]
    fn test_provider_detection() {
        assert_eq!(
            OidcProvider::from_issuer("https://dev-123456.okta.com"),
            OidcProvider::Okta
        );
        assert_eq!(
            OidcProvider::from_issuer("https://tenant.auth0.com"),
            OidcProvider::Auth0
        );
        assert_eq!(
            OidcProvider::from_issuer("https://login.microsoftonline.com/tenant"),
            OidcProvider::AzureAd
        );
        assert_eq!(
            OidcProvider::from_issuer("https://keycloak.example.com/realms/master"),
            OidcProvider::Keycloak
        );
        assert_eq!(
            OidcProvider::from_issuer("https://cognito-idp.us-east-1.amazonaws.com/pool"),
            OidcProvider::Cognito
        );
        assert_eq!(
            OidcProvider::from_issuer("https://accounts.google.com"),
            OidcProvider::Google
        );
    }

    #[test]
    fn test_oidc_configuration_parsing() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code", "id_token", "token"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "frontchannel_logout_supported": true
        }"#;

        let config = OidcConfiguration::from_json(json).unwrap();
        assert_eq!(config.issuer, Some("https://auth.example.com".to_string()));
        assert!(config
            .response_types_supported
            .contains(&"code".to_string()));
        assert!(config
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
        assert!(config
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
        assert!(config.frontchannel_logout_supported);
    }

    #[test]
    fn test_insecure_algorithm_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.id_token_signing_alg_values_supported = vec!["none".to_string()];
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_insecure_algorithms(&config, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("None Algorithm")));
    }

    #[test]
    fn test_algorithm_confusion_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.id_token_signing_alg_values_supported =
            vec!["RS256".to_string(), "HS256".to_string()];
        config.jwks_uri = Some("https://example.com/.well-known/jwks.json".to_string());
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_algorithm_confusion_risk(&config, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns
            .iter()
            .any(|v| v.vuln_type.contains("Algorithm Confusion")));
    }

    #[test]
    fn test_missing_pkce_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.code_challenge_methods_supported = vec![];
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_pkce_support(&config, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("PKCE")));
    }

    #[test]
    fn test_implicit_flow_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.response_types_supported = vec!["code".to_string(), "token".to_string()];
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_implicit_flow_risks(&config, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Implicit Flow")));
    }

    #[test]
    fn test_id_token_in_url_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());

        let mut vulns = Vec::new();
        scanner.check_id_token_in_url(
            "https://app.example.com/callback#id_token=eyJhbGc...",
            &mut vulns,
        );

        assert!(!vulns.is_empty());
        assert!(vulns
            .iter()
            .any(|v| v.vuln_type.contains("ID Token in URL")));
    }

    #[test]
    fn test_client_secret_exposure() {
        let scanner = OidcScanner::new(create_mock_http_client());

        let response = HttpResponse {
            status_code: 200,
            body: r#"const config = { client_secret: "abc123def456" };"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_client_secret_exposure(&response, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Client Secret")));
    }

    #[test]
    fn test_missing_logout_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.end_session_endpoint = None;
        config.frontchannel_logout_supported = false;
        config.backchannel_logout_supported = false;
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_logout_implementation(&config, "https://example.com", &mut vulns);

        assert!(vulns.len() >= 1);
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Logout")));
    }

    #[test]
    fn test_http_endpoint_detection() {
        let scanner = OidcScanner::new(create_mock_http_client());
        let mut config = OidcConfiguration::default();
        config.authorization_endpoint = Some("http://auth.example.com/authorize".to_string());
        config.token_endpoint = Some("https://auth.example.com/token".to_string());
        config.provider = OidcProvider::Generic;

        let mut vulns = Vec::new();
        scanner.check_configuration_security(&config, "https://example.com", &mut vulns);

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("HTTP")));
    }
}
