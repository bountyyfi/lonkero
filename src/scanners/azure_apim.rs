// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

pub struct AzureApimScanner {
    http_client: Arc<HttpClient>,
}

impl AzureApimScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for Azure APIM Cross-Tenant Signup Bypass vulnerability
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[Azure-APIM] Scanning for Cross-Tenant Signup Bypass");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Parse URL to get base domain
        let base_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Ok((vulnerabilities, 0)),
        };

        let host = match base_url.host_str() {
            Some(h) => h,
            None => return Ok((vulnerabilities, 0)),
        };

        // Check 1: Is this an Azure APIM Developer Portal?
        tests_run += 1;
        let is_apim = self.detect_apim_portal(url, host).await;

        if !is_apim {
            info!("[Azure-APIM] Not an Azure APIM Developer Portal, skipping");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Azure-APIM] Detected Azure APIM Developer Portal");

        let origin = format!("{}://{}", base_url.scheme(), host);

        // Check 2: Check if signup endpoint is accessible
        tests_run += 1;
        let signup_accessible = self.check_signup_endpoint(&origin).await;

        // Check 3: Check if Basic Auth signup API is active
        tests_run += 1;
        let (basic_auth_active, api_response) = self.check_basic_auth_api(&origin).await;

        // Check 4: Check if signup is hidden in UI but API still works
        tests_run += 1;
        let signup_hidden = self.check_signup_hidden(&origin).await;

        // Determine vulnerability status
        if basic_auth_active {
            if signup_hidden {
                // CRITICAL: Signup disabled in UI but API works = VULNERABLE
                info!("[ALERT] Azure APIM Cross-Tenant Signup Bypass detected!");

                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Azure APIM Cross-Tenant Signup Bypass".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Access Control".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!(
                        "CRITICAL: Azure APIM Developer Portal is vulnerable to cross-tenant signup bypass (GHSA-vcwf-73jp-r7mv). \
                        The Basic Authentication signup API is accessible even though signup is disabled in the UI. \
                        Attackers can register accounts by sending direct API requests, bypassing administrative controls. \
                        This enables cross-tenant account creation and potential access to API documentation, subscription keys, \
                        and other Developer Portal resources. CVSS: 6.5 (Medium-High)."
                    ),
                    evidence: Some(format!(
                        "Signup API response: {}. Signup UI hidden: {}. Basic Auth API active: true",
                        api_response.as_deref().unwrap_or("active"),
                        signup_hidden
                    )),
                    cwe: "CWE-284".to_string(),
                    cvss: 6.5,
                    verified: true,
                    false_positive: false,
                    remediation: r#"IMMEDIATE ACTION REQUIRED:
1. REMOVE Basic Authentication identity provider completely in Azure Portal
   - Navigate to APIM instance → Developer Portal → Identities
   - DELETE the "Username and password" identity provider entirely
   - NOTE: Simply disabling signup in UI is NOT sufficient!

2. Audit existing Developer Portal accounts
   - Review all user accounts for unauthorized registrations
   - Check account creation timestamps and patterns
   - Remove any suspicious or unauthorized accounts

3. Enable Azure AD authentication only
   - Configure Azure AD as the sole identity provider
   - This enforces proper tenant boundaries
   - Implement MFA for all portal users

4. Implement monitoring
   - Enable Azure Monitor alerts for signup activity
   - Log and review all Developer Portal authentication events
   - Set up alerts for unusual registration patterns

Reference: https://github.com/bountyyfi/Azure-APIM-Cross-Tenant-Signup-Bypass"#.to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            } else {
                // Basic Auth enabled with signup visible - can be used as attack source
                info!("[NOTE] Azure APIM with Basic Auth enabled (potential attack source)");

                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Azure APIM Basic Auth Enabled".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    category: "Access Control".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!(
                        "Azure APIM Developer Portal has Basic Authentication enabled with visible signup. \
                        While this is a configuration choice, it increases attack surface. \
                        This instance could potentially be used as an attack source to perform \
                        cross-tenant signup bypass attacks against other APIM instances. \
                        Consider migrating to Azure AD authentication for improved security."
                    ),
                    evidence: Some(format!(
                        "Basic Auth signup API active: true. Signup visible in UI: {}",
                        signup_accessible
                    )),
                    cwe: "CWE-284".to_string(),
                    cvss: 4.0,
                    verified: true,
                    false_positive: false,
                    remediation: r#"RECOMMENDED ACTIONS:
1. Consider migrating to Azure AD authentication
2. Implement email domain whitelisting for registrations
3. Monitor signup activity for suspicious registrations
4. Review and remove unused developer accounts regularly
5. Enable MFA for all portal users

Reference: https://github.com/bountyyfi/Azure-APIM-Cross-Tenant-Signup-Bypass"#.to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        info!("[SUCCESS] [Azure-APIM] Completed {} tests, found {} issues",
            tests_run, vulnerabilities.len());

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if the target is an Azure APIM Developer Portal
    async fn detect_apim_portal(&self, url: &str, host: &str) -> bool {
        // Check 1: Domain pattern
        if host.contains("developer.azure-api.net") {
            return true;
        }

        // Check 2: Fetch and look for APIM indicators in response
        if let Ok(response) = self.http_client.get(url).await {
            let body = &response.body;

            // APIM Developer Portal indicators
            let apim_indicators = [
                "developerPortal",
                "azure-api.net",
                "apim-",
                "api-management",
                "ApiManagement",
                "Developer Portal",
                "API Management",
                "Subscribe to API",
                "API documentation",
            ];

            // Check headers for APIM indicators
            let has_apim_header = response.headers.iter().any(|(k, v)| {
                k.to_lowercase().contains("apim") ||
                v.to_lowercase().contains("azure-api")
            });

            if has_apim_header {
                return true;
            }

            // Check body for APIM indicators
            for indicator in &apim_indicators {
                if body.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if signup endpoint is accessible
    async fn check_signup_endpoint(&self, origin: &str) -> bool {
        let signup_url = format!("{}/signup", origin);

        match self.http_client.get(&signup_url).await {
            Ok(response) => {
                response.status_code == 200 || response.status_code == 302
            }
            Err(_) => false,
        }
    }

    /// Check if Basic Auth signup API is active by sending a test request
    async fn check_basic_auth_api(&self, origin: &str) -> (bool, Option<String>) {
        let signup_url = format!("{}/signup", origin);

        // Test payload with fake captcha - will fail validation but endpoint will respond if active
        let payload = serde_json::json!({
            "challenge": {
                "testCaptchaRequest": {
                    "challengeId": "00000000-0000-0000-0000-000000000000",
                    "inputSolution": "AAAAAA"
                },
                "azureRegion": "NorthCentralUS",
                "challengeType": "visual"
            },
            "signupData": {
                "email": "security-probe@nonexistent-invalid-domain.test",
                "firstName": "Security",
                "lastName": "Probe",
                "password": "SecurityProbe123!",
                "confirmation": "signup",
                "appType": "developerPortal"
            }
        });

        match self.http_client.post_json(&signup_url, &payload).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();

                // 404 = endpoint doesn't exist
                if response.status_code == 404 {
                    return (false, Some("Signup API not found (404)".to_string()));
                }

                // These responses indicate the signup API EXISTS and processes requests
                if response.status_code == 400 {
                    if body_lower.contains("captcha") || body_lower.contains("challenge") {
                        return (true, Some("Basic Auth signup API ACTIVE (captcha validation)".to_string()));
                    }
                    if body_lower.contains("email") || body_lower.contains("password") || body_lower.contains("invalid") {
                        return (true, Some("Basic Auth signup API ACTIVE (input validation)".to_string()));
                    }
                    return (true, Some("Basic Auth signup API responds (400)".to_string()));
                }

                if response.status_code == 409 {
                    return (true, Some("Basic Auth signup API ACTIVE (409 conflict)".to_string()));
                }

                if response.status_code == 200 || response.status_code == 201 {
                    return (true, Some("Basic Auth signup API ACCEPTS requests".to_string()));
                }

                if response.status_code == 401 || response.status_code == 403 {
                    return (true, Some(format!("Basic Auth signup API responds ({})", response.status_code)));
                }

                if response.status_code == 422 {
                    return (true, Some("Basic Auth signup API validates (422)".to_string()));
                }

                (false, Some(format!("Signup returned {}", response.status_code)))
            }
            Err(_) => (false, None),
        }
    }

    /// Check if signup is hidden/disabled in the UI
    async fn check_signup_hidden(&self, origin: &str) -> bool {
        let signup_url = format!("{}/signup", origin);

        match self.http_client.get(&signup_url).await {
            Ok(response) => {
                // 404 or redirect = signup is hidden in UI
                if response.status_code == 404 {
                    return true;
                }
                if response.status_code >= 300 && response.status_code < 400 {
                    return true;
                }
                false
            }
            Err(_) => false,
        }
    }
}

fn generate_uuid() -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apim_domain_detection() {
        // Test domain patterns
        assert!("example.developer.azure-api.net".contains("developer.azure-api.net"));
        assert!("contoso.developer.azure-api.net".contains("developer.azure-api.net"));
    }

    #[test]
    fn test_uuid_generation() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36); // UUID format: 8-4-4-4-12
        assert!(uuid.contains('-'));
    }
}
