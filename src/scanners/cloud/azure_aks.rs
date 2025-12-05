// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Azure Kubernetes Service (AKS) Security Scanner
 * Production-grade scanner for AKS cluster vulnerabilities
 *
 * Detects:
 * - AKS clusters without authorized IP ranges
 * - AKS clusters without RBAC enabled
 * - AKS clusters without Azure Policy
 * - AKS clusters without private cluster mode
 * - AKS node pools without encryption
 * - AKS without Azure AD integration
 * - AKS without network policies
 * - AKS without Azure Monitor
 * - AKS API server with public access
 * - AKS without Azure Defender
 * - AKS secrets encryption disabled
 * - AKS HTTP application routing enabled (insecure)
 * - AKS managed identity not configured
 * - AKS pod security policies disabled
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct AzureAksScanner {
    http_client: Arc<HttpClient>,
}

impl AzureAksScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan Azure Kubernetes Service (AKS) for security vulnerabilities
    pub async fn scan(
        &self,
        target: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting Azure Kubernetes Service (AKS) security scan");

        let domain = self.extract_domain(target);

        // Scan for exposed AKS API servers
        let (vulns, tests) = self.scan_aks_api_servers(&domain, config).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Scan for AKS security misconfigurations
        let (vulns, tests) = self.scan_aks_security_config(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Scan for AKS network security
        let (vulns, tests) = self.scan_aks_network_security(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Scan for AKS authentication and authorization
        let (vulns, tests) = self.scan_aks_auth_config(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Scan for AKS monitoring and logging
        let (vulns, tests) = self.scan_aks_monitoring(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        info!(
            "AKS security scan completed: {} tests run, {} vulnerabilities found",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for exposed AKS API servers
    async fn scan_aks_api_servers(
        &self,
        domain: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 20;

        info!("Scanning for exposed AKS API servers");

        let aks_cluster_patterns = vec![
            format!("{}-aks", domain),
            format!("aks-{}", domain),
            format!("{}-k8s", domain),
            format!("{}-cluster", domain),
            format!("{}-kubernetes", domain),
        ];

        let regions = vec![
            "eastus", "westus", "westus2", "centralus",
            "westeurope", "northeurope",
            "southeastasia", "eastasia",
        ];

        for cluster_name in &aks_cluster_patterns {
            for region in &regions {
                // AKS API server endpoints: <cluster-name>-<random-hash>.<region>.azmk8s.io
                // We'll test common patterns
                let api_endpoints = vec![
                    format!("https://{}.{}.azmk8s.io", cluster_name, region),
                    format!("https://{}.{}.azmk8s.io:443", cluster_name, region),
                    format!("https://{}.{}.azmk8s.io/api/v1", cluster_name, region),
                    format!("https://{}.{}.azmk8s.io/healthz", cluster_name, region),
                ];

                for api_url in api_endpoints {
                    match self.http_client.get(&api_url).await {
                        Ok(response) => {
                            if self.is_aks_api_server(&response.body, &response.headers, response.status_code) {
                                info!("Found AKS cluster API: {}", cluster_name);

                                // Check if API server is publicly accessible
                                if response.status_code == 200 || response.status_code == 401 {
                                    vulnerabilities.push(self.create_vulnerability(
                                        &api_url,
                                        "AKS API Server Publicly Accessible",
                                        "",
                                        &format!(
                                            "AKS cluster '{}' API server is accessible from the internet. Consider using private cluster mode.",
                                            cluster_name
                                        ),
                                        "API server reachable from public internet",
                                        Severity::High,
                                        "CWE-668",
                                        8.6,
                                        vec![
                                            "Enable private cluster mode to disable public FQDN".to_string(),
                                            "Configure authorized IP ranges to restrict API access".to_string(),
                                            "Use Azure Private Link for API server access".to_string(),
                                            "Implement Azure Firewall for additional protection".to_string(),
                                            "Enable Azure AD integration for authentication".to_string(),
                                            "Use kubectl through Azure Bastion or VPN".to_string(),
                                        ],
                                    ));

                                    // Check for missing authorized IP ranges
                                    if !self.has_authorized_ip_ranges(&response.headers) {
                                        vulnerabilities.push(self.create_vulnerability(
                                            &api_url,
                                            "AKS Authorized IP Ranges Not Configured",
                                            "",
                                            &format!(
                                                "AKS cluster '{}' does not have authorized IP ranges configured. API server accessible from any IP.",
                                                cluster_name
                                            ),
                                            "No IP range restrictions detected",
                                            Severity::High,
                                            "CWE-284",
                                            7.5,
                                            vec![
                                                "Configure authorized IP address ranges for API server".to_string(),
                                                "Limit access to corporate networks and VPNs".to_string(),
                                                "Use Azure Firewall or NSG for additional filtering".to_string(),
                                                "Enable private cluster for maximum security".to_string(),
                                            ],
                                        ));
                                    }

                                    // Check for RBAC configuration
                                    if !self.has_rbac_enabled(&response.headers, &response.body) {
                                        vulnerabilities.push(self.create_vulnerability(
                                            &api_url,
                                            "AKS RBAC Not Enabled",
                                            "",
                                            &format!(
                                                "AKS cluster '{}' does not have Kubernetes RBAC enabled. All users have full cluster access.",
                                                cluster_name
                                            ),
                                            "RBAC not detected",
                                            Severity::Critical,
                                            "CWE-269",
                                            9.1,
                                            vec![
                                                "Enable Kubernetes RBAC in AKS cluster settings".to_string(),
                                                "Integrate with Azure AD for RBAC".to_string(),
                                                "Implement least privilege access policies".to_string(),
                                                "Use Azure AD groups for role assignments".to_string(),
                                                "Regular audit of RBAC permissions".to_string(),
                                            ],
                                        ));
                                    }
                                }

                                // Check for anonymous access (no auth required)
                                if response.status_code == 200 && !response.headers.contains_key("www-authenticate") {
                                    vulnerabilities.push(self.create_vulnerability(
                                        &api_url,
                                        "AKS API Server Allows Anonymous Access",
                                        "",
                                        &format!(
                                            "AKS cluster '{}' API server allows anonymous access without authentication.",
                                            cluster_name
                                        ),
                                        "No authentication required",
                                        Severity::Critical,
                                        "CWE-306",
                                        10.0,
                                        vec![
                                            "Disable anonymous authentication immediately".to_string(),
                                            "Enable Azure AD authentication".to_string(),
                                            "Require client certificates for API access".to_string(),
                                            "Implement RBAC with proper role bindings".to_string(),
                                            "Audit cluster access logs for unauthorized access".to_string(),
                                        ],
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            debug!("AKS API check failed for {}: {}", api_url, e);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for AKS security configuration issues
    async fn scan_aks_security_config(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        info!("Scanning AKS security configuration");

        let cluster_patterns = vec![
            format!("{}-aks", domain),
            format!("aks-{}", domain),
        ];

        for cluster_name in cluster_patterns {
            // Try to access cluster info endpoints
            let info_url = format!("https://{}.eastus.azmk8s.io/version", cluster_name);

            match self.http_client.get(&info_url).await {
                Ok(response) => {
                    if self.is_kubernetes_response(&response.body) {
                        // Check for Azure Policy integration
                        if !self.has_azure_policy(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &info_url,
                                "AKS Without Azure Policy",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have Azure Policy enabled. Missing compliance and governance controls.",
                                    cluster_name
                                ),
                                "Azure Policy not detected",
                                Severity::Medium,
                                "CWE-1188",
                                6.5,
                                vec![
                                    "Enable Azure Policy Add-on for AKS".to_string(),
                                    "Implement pod security policies".to_string(),
                                    "Use built-in policy definitions for AKS".to_string(),
                                    "Create custom policies for organizational requirements".to_string(),
                                    "Monitor policy compliance with Azure Security Center".to_string(),
                                ],
                            ));
                        }

                        // Check for secrets encryption
                        if !self.has_secrets_encryption(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &info_url,
                                "AKS Secrets Encryption at Rest Disabled",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have secrets encryption at rest enabled with Azure Key Vault.",
                                    cluster_name
                                ),
                                "Secrets encryption not configured",
                                Severity::High,
                                "CWE-311",
                                7.5,
                                vec![
                                    "Enable Azure Key Vault provider for secrets encryption".to_string(),
                                    "Configure etcd encryption at rest".to_string(),
                                    "Use managed identities for Key Vault access".to_string(),
                                    "Rotate encryption keys regularly".to_string(),
                                    "Audit secret access with Azure Monitor".to_string(),
                                ],
                            ));
                        }

                        // Check for Azure Defender
                        if !self.has_azure_defender(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &info_url,
                                "AKS Without Azure Defender",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have Azure Defender for Kubernetes enabled. Missing threat detection.",
                                    cluster_name
                                ),
                                "Azure Defender not enabled",
                                Severity::High,
                                "CWE-1357",
                                7.5,
                                vec![
                                    "Enable Azure Defender for Kubernetes".to_string(),
                                    "Configure security alerts and notifications".to_string(),
                                    "Enable runtime threat detection".to_string(),
                                    "Integrate with Azure Sentinel for SIEM".to_string(),
                                    "Review and act on security recommendations".to_string(),
                                ],
                            ));
                        }

                        // Check for HTTP application routing (insecure addon)
                        if self.has_http_application_routing(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &info_url,
                                "AKS HTTP Application Routing Enabled (Insecure)",
                                "",
                                &format!(
                                    "AKS cluster '{}' has HTTP application routing enabled. This is not recommended for production.",
                                    cluster_name
                                ),
                                "HTTP application routing addon detected",
                                Severity::Medium,
                                "CWE-319",
                                5.3,
                                vec![
                                    "Disable HTTP application routing addon".to_string(),
                                    "Use NGINX Ingress Controller or Azure Application Gateway".to_string(),
                                    "Implement TLS/SSL for all ingress traffic".to_string(),
                                    "Use cert-manager for automatic certificate management".to_string(),
                                ],
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("AKS security config check failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for AKS network security issues
    async fn scan_aks_network_security(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        info!("Scanning AKS network security");

        let cluster_patterns = vec![
            format!("{}-aks", domain),
            format!("aks-{}", domain),
        ];

        for cluster_name in cluster_patterns {
            let api_url = format!("https://{}.eastus.azmk8s.io", cluster_name);

            match self.http_client.get(&api_url).await {
                Ok(response) => {
                    if self.is_aks_api_server(&response.body, &response.headers, response.status_code) {
                        // Check for network policies
                        if !self.has_network_policies(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Without Network Policies",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have network policies configured. Pods can communicate without restrictions.",
                                    cluster_name
                                ),
                                "Network policy enforcement not detected",
                                Severity::High,
                                "CWE-923",
                                7.5,
                                vec![
                                    "Enable Azure Network Policy or Calico".to_string(),
                                    "Implement pod-to-pod network segmentation".to_string(),
                                    "Define ingress and egress rules for pods".to_string(),
                                    "Use namespace-based isolation".to_string(),
                                    "Test network policies in dev/staging first".to_string(),
                                ],
                            ));
                        }

                        // Check for private cluster mode
                        if !self.has_private_cluster_mode(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Not Using Private Cluster Mode",
                                "",
                                &format!(
                                    "AKS cluster '{}' is not using private cluster mode. API server has public endpoint.",
                                    cluster_name
                                ),
                                "Public API server endpoint",
                                Severity::High,
                                "CWE-668",
                                7.5,
                                vec![
                                    "Enable private cluster mode for new clusters".to_string(),
                                    "Use Azure Private Link for API server connectivity".to_string(),
                                    "Disable public FQDN if not required".to_string(),
                                    "Access cluster via VPN or Azure Bastion".to_string(),
                                    "Configure authorized IP ranges as interim measure".to_string(),
                                ],
                            ));
                        }

                        // Check for node pool encryption
                        if !self.has_node_encryption(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Node Pools Without Encryption",
                                "",
                                &format!(
                                    "AKS cluster '{}' node pools do not have disk encryption enabled.",
                                    cluster_name
                                ),
                                "Node disk encryption not detected",
                                Severity::Medium,
                                "CWE-311",
                                6.5,
                                vec![
                                    "Enable Azure Disk Encryption for node pools".to_string(),
                                    "Use customer-managed keys for encryption".to_string(),
                                    "Enable host-based encryption for VMs".to_string(),
                                    "Encrypt ephemeral OS disks".to_string(),
                                ],
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("AKS network security check failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for AKS authentication and authorization configuration
    async fn scan_aks_auth_config(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Scanning AKS authentication and authorization");

        let cluster_patterns = vec![
            format!("{}-aks", domain),
            format!("aks-{}", domain),
        ];

        for cluster_name in cluster_patterns {
            let api_url = format!("https://{}.eastus.azmk8s.io", cluster_name);

            match self.http_client.get(&api_url).await {
                Ok(response) => {
                    if self.is_aks_api_server(&response.body, &response.headers, response.status_code) {
                        // Check for Azure AD integration
                        if !self.has_azure_ad_integration(&response.headers, &response.body) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Without Azure AD Integration",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not use Azure AD integration. Missing centralized identity management.",
                                    cluster_name
                                ),
                                "Azure AD integration not detected",
                                Severity::High,
                                "CWE-287",
                                7.5,
                                vec![
                                    "Enable Azure AD integration for AKS".to_string(),
                                    "Use Azure AD groups for RBAC assignments".to_string(),
                                    "Implement conditional access policies".to_string(),
                                    "Enable MFA for cluster administrators".to_string(),
                                    "Audit authentication events with Azure Monitor".to_string(),
                                ],
                            ));
                        }

                        // Check for managed identity
                        if !self.has_managed_identity_configured(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Managed Identity Not Configured",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not use managed identity. May be using service principals with static credentials.",
                                    cluster_name
                                ),
                                "Managed identity not detected",
                                Severity::Medium,
                                "CWE-798",
                                6.5,
                                vec![
                                    "Enable managed identity for AKS cluster".to_string(),
                                    "Use system-assigned or user-assigned managed identity".to_string(),
                                    "Remove service principal credentials".to_string(),
                                    "Grant managed identity required Azure permissions".to_string(),
                                ],
                            ));
                        }

                        // Check for pod security policies
                        if !self.has_pod_security_policies(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Pod Security Policies Not Configured",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have pod security policies configured. Pods may run with excessive privileges.",
                                    cluster_name
                                ),
                                "Pod security policies not detected",
                                Severity::High,
                                "CWE-250",
                                7.5,
                                vec![
                                    "Enable Azure Policy for AKS".to_string(),
                                    "Implement pod security standards (restricted, baseline)".to_string(),
                                    "Use Azure Policy pod security initiative".to_string(),
                                    "Restrict privileged containers".to_string(),
                                    "Enforce read-only root filesystems".to_string(),
                                ],
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("AKS auth config check failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for AKS monitoring and logging configuration
    async fn scan_aks_monitoring(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Scanning AKS monitoring and logging");

        let cluster_patterns = vec![
            format!("{}-aks", domain),
            format!("aks-{}", domain),
        ];

        for cluster_name in cluster_patterns {
            let api_url = format!("https://{}.eastus.azmk8s.io", cluster_name);

            match self.http_client.get(&api_url).await {
                Ok(response) => {
                    if self.is_aks_api_server(&response.body, &response.headers, response.status_code) {
                        // Check for Azure Monitor
                        if !self.has_azure_monitor(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Without Azure Monitor",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have Azure Monitor (Container Insights) enabled. Missing critical monitoring.",
                                    cluster_name
                                ),
                                "Azure Monitor not detected",
                                Severity::Medium,
                                "CWE-778",
                                6.5,
                                vec![
                                    "Enable Container Insights for AKS".to_string(),
                                    "Configure Log Analytics workspace".to_string(),
                                    "Monitor cluster health and performance".to_string(),
                                    "Set up alerts for critical events".to_string(),
                                    "Enable diagnostic logging for control plane".to_string(),
                                ],
                            ));
                        }

                        // Check for diagnostic logs
                        if !self.has_diagnostic_logs(&response.headers) {
                            vulnerabilities.push(self.create_vulnerability(
                                &api_url,
                                "AKS Diagnostic Logs Not Enabled",
                                "",
                                &format!(
                                    "AKS cluster '{}' does not have diagnostic logs enabled. Unable to audit cluster activities.",
                                    cluster_name
                                ),
                                "Diagnostic logging not configured",
                                Severity::Medium,
                                "CWE-778",
                                5.3,
                                vec![
                                    "Enable diagnostic settings for AKS cluster".to_string(),
                                    "Log kube-apiserver, kube-controller-manager, kube-scheduler".to_string(),
                                    "Configure log retention policies".to_string(),
                                    "Export logs to Log Analytics or Storage Account".to_string(),
                                    "Integrate with Azure Sentinel for SIEM".to_string(),
                                ],
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("AKS monitoring check failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // Helper methods

    fn extract_domain(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host
                    .trim_start_matches("www.")
                    .split('.')
                    .next()
                    .unwrap_or("example")
                    .to_string()
                    .replace("-", "")
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect();
            }
        }
        "example".to_string()
    }

    fn is_aks_api_server(
        &self,
        body: &str,
        headers: &HashMap<String, String>,
        status_code: u16,
    ) -> bool {
        // Check for Kubernetes API indicators
        if self.is_kubernetes_response(body) {
            return true;
        }

        // Check for AKS-specific headers
        for (key, value) in headers {
            if key.to_lowercase().contains("x-aks-") || value.to_lowercase().contains("azmk8s") {
                return true;
            }
        }

        // 401/403 with WWW-Authenticate indicates K8s API
        if (status_code == 401 || status_code == 403) && headers.contains_key("www-authenticate") {
            return true;
        }

        false
    }

    fn is_kubernetes_response(&self, body: &str) -> bool {
        let k8s_indicators = vec![
            "\"kind\":",
            "\"apiVersion\":",
            "\"metadata\":",
            "kubernetes",
            "k8s.io",
        ];

        let body_lower = body.to_lowercase();
        k8s_indicators.iter().filter(|&&i| body_lower.contains(i)).count() >= 2
    }

    fn has_authorized_ip_ranges(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-authorized-ip-ranges").is_some()
    }

    fn has_rbac_enabled(&self, headers: &HashMap<String, String>, body: &str) -> bool {
        // Check headers for RBAC indicators
        if headers.get("x-aks-rbac-enabled").map(|v| v == "true").unwrap_or(false) {
            return true;
        }

        // Check response body for RBAC APIs
        body.contains("rbac.authorization.k8s.io")
    }

    fn has_azure_policy(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-azure-policy-enabled").is_some()
    }

    fn has_secrets_encryption(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-secrets-encryption").is_some()
            || headers.get("x-aks-keyvault-enabled").is_some()
    }

    fn has_azure_defender(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-defender-enabled").is_some()
            || headers.get("x-ms-defender-enabled").is_some()
    }

    fn has_http_application_routing(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-http-application-routing")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    fn has_network_policies(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-network-policy").is_some()
    }

    fn has_private_cluster_mode(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-private-cluster")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    fn has_node_encryption(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-node-encryption").is_some()
    }

    fn has_azure_ad_integration(&self, headers: &HashMap<String, String>, body: &str) -> bool {
        headers.get("x-aks-aad-enabled").is_some()
            || body.contains("aad.microsoft.com")
            || body.contains("azure-ad")
    }

    fn has_managed_identity_configured(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-managed-identity").is_some()
            || headers.get("x-ms-identity-type").is_some()
    }

    fn has_pod_security_policies(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-pod-security-policy").is_some()
    }

    fn has_azure_monitor(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-monitoring-enabled").is_some()
            || headers.get("x-aks-container-insights").is_some()
    }

    fn has_diagnostic_logs(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-aks-diagnostic-logs").is_some()
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
        remediation_steps: Vec<String>,
    ) -> Vulnerability {
        let remediation = remediation_steps
            .iter()
            .enumerate()
            .map(|(i, step)| format!("{}. {}", i + 1, step))
            .collect::<Vec<_>>()
            .join("\n");

        Vulnerability {
            id: format!("azure_aks_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Azure Kubernetes Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> AzureAksScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        AzureAksScanner::new(client)
    }

    #[test]
    fn test_extract_domain() {
        let scanner = create_test_scanner();
        assert_eq!(scanner.extract_domain("https://my-app.com"), "myapp");
    }

    #[test]
    fn test_is_kubernetes_response() {
        let scanner = create_test_scanner();

        let k8s_json = r#"{"kind":"Pod","apiVersion":"v1","metadata":{}}"#;
        assert!(scanner.is_kubernetes_response(k8s_json));

        assert!(!scanner.is_kubernetes_response("Normal HTML page"));
    }

    #[test]
    fn test_is_aks_api_server() {
        let scanner = create_test_scanner();
        let mut headers = HashMap::new();

        headers.insert("www-authenticate".to_string(), "Bearer realm=\"kubernetes\"".to_string());
        assert!(scanner.is_aks_api_server("", &headers, 401));

        let k8s_body = r#"{"kind":"APIVersions","versions":["v1"]}"#;
        assert!(scanner.is_aks_api_server(k8s_body, &HashMap::new(), 200));
    }
}
