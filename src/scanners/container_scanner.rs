// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

pub struct ContainerScanner {
    http_client: Arc<HttpClient>,
}

impl ContainerScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for container security vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing container security vulnerabilities");

        let (vulns, tests) = self.test_docker_api_exposure(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_kubernetes_api_exposure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_container_registry_exposure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_container_secrets_exposure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for exposed Docker API
    async fn test_docker_api_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing for Docker API exposure");

        let docker_endpoints = vec![
            ("/v1.40/containers/json", "Docker API v1.40"),
            ("/v1.41/containers/json", "Docker API v1.41"),
            ("/containers/json", "Docker API"),
            ("/images/json", "Docker Images API"),
            ("/info", "Docker Info"),
            ("/version", "Docker Version"),
            ("/_ping", "Docker Ping"),
            ("/events", "Docker Events"),
        ];

        for (endpoint, api_name) in docker_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.is_docker_api_response(&response.body) {
                        info!("Exposed Docker API detected: {}", api_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Exposed Docker API",
                            "",
                            &format!("{} is publicly accessible without authentication", api_name),
                            &format!("Docker API accessible at {}", endpoint),
                            Severity::Critical,
                            "CWE-306",
                            9.8,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", endpoint, e);
                }
            }
        }

        // Skip port scanning for regular web targets - only test if no vulns found on standard endpoints
        // Use short timeout (3s) for port checks to avoid blocking on closed ports
        if vulnerabilities.is_empty() {
            let docker_ports = vec!["2375", "2376"];
            for port in docker_ports {
                if let Some(base_url) = self.extract_base_with_port(url, port) {
                    let test_url = format!("{}/_ping", base_url);

                    // Use short timeout for port checks
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        self.http_client.get(&test_url),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            if response.status_code == 200 && response.body.contains("OK") {
                                info!("Docker daemon exposed on port {}", port);
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Exposed Docker Daemon",
                                    "",
                                    &format!(
                                        "Docker daemon exposed on port {} without authentication",
                                        port
                                    ),
                                    &format!("Docker daemon accessible at port {}", port),
                                    Severity::Critical,
                                    "CWE-306",
                                    10.0,
                                ));
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Docker port {} check failed: {}", port, e);
                        }
                        Err(_) => {
                            debug!("Docker port {} check timed out (3s)", port);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for exposed Kubernetes API
    async fn test_kubernetes_api_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        debug!("Testing for Kubernetes API exposure");

        let k8s_endpoints = vec![
            ("/api/v1", "Kubernetes API"),
            ("/api/v1/namespaces", "K8s Namespaces"),
            ("/api/v1/pods", "K8s Pods"),
            ("/api/v1/secrets", "K8s Secrets"),
            ("/api/v1/services", "K8s Services"),
            ("/apis", "K8s APIs"),
            ("/healthz", "K8s Health"),
            ("/version", "K8s Version"),
            ("/metrics", "K8s Metrics"),
            ("/swagger.json", "K8s Swagger"),
        ];

        for (endpoint, api_name) in k8s_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.is_kubernetes_response(&response.body) {
                        info!("Exposed Kubernetes API detected: {}", api_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Exposed Kubernetes API",
                            "",
                            &format!("{} is publicly accessible", api_name),
                            &format!("Kubernetes API accessible at {}", endpoint),
                            Severity::Critical,
                            "CWE-306",
                            9.8,
                        ));
                        break;
                    }

                    if response.status_code == 403 && self.is_kubernetes_response(&response.body) {
                        info!("Kubernetes API found (forbidden): {}", api_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Kubernetes API Exposed (Auth Required)",
                            "",
                            &format!("{} is exposed but requires authentication", api_name),
                            &format!(
                                "Kubernetes API detected at {} (may be misconfigured)",
                                endpoint
                            ),
                            Severity::Medium,
                            "CWE-200",
                            5.3,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", endpoint, e);
                }
            }
        }

        // Skip port scanning if we already found K8s on standard endpoints
        // Use short timeout (3s) for port checks to avoid blocking on closed ports
        if vulnerabilities.is_empty() {
            let k8s_ports = vec!["6443", "8080", "10250", "10255"];
            for port in k8s_ports {
                if let Some(base_url) = self.extract_base_with_port(url, port) {
                    let test_url = format!("{}/healthz", base_url);

                    // Use short timeout for port checks
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        self.http_client.get(&test_url),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            if response.status_code == 200
                                && response.body.to_lowercase().contains("ok")
                            {
                                info!("Kubernetes component exposed on port {}", port);
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Exposed Kubernetes Component",
                                    "",
                                    &format!("Kubernetes component exposed on port {}", port),
                                    &format!("K8s service accessible at port {}", port),
                                    Severity::High,
                                    "CWE-306",
                                    8.6,
                                ));
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("K8s port {} check failed: {}", port, e);
                        }
                        Err(_) => {
                            debug!("K8s port {} check timed out (3s)", port);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for container registry exposure
    async fn test_container_registry_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing for container registry exposure");

        let registry_endpoints = vec![
            ("/v2/", "Docker Registry v2"),
            ("/v2/_catalog", "Registry Catalog"),
            ("/v2/library/", "Registry Library"),
            ("/v1/repositories/", "Registry Repositories"),
            ("/v1/_ping", "Registry Ping"),
        ];

        for (endpoint, registry_name) in registry_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200
                        && self.is_registry_response(&response.body, &response.headers)
                    {
                        info!("Exposed container registry detected: {}", registry_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Exposed Container Registry",
                            "",
                            &format!("{} is publicly accessible", registry_name),
                            &format!("Container registry accessible at {}", endpoint),
                            Severity::High,
                            "CWE-306",
                            8.1,
                        ));
                        break;
                    }

                    if response.status_code == 401
                        && response
                            .headers
                            .get("www-authenticate")
                            .map(|v| v.to_lowercase().contains("bearer"))
                            .unwrap_or(false)
                    {
                        info!(
                            "Container registry found (auth required): {}",
                            registry_name
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Container Registry Detected",
                            "",
                            &format!("{} detected (authentication required)", registry_name),
                            &format!("Registry at {} may have weak authentication", endpoint),
                            Severity::Low,
                            "CWE-200",
                            3.7,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Registry check failed: {}", e);
                }
            }
        }

        // Skip port scanning if we already found registry on standard endpoints
        // Use short timeout (3s) for port checks
        if vulnerabilities.is_empty() {
            let registry_ports = vec!["5000", "5001"];
            for port in registry_ports {
                if let Some(base_url) = self.extract_base_with_port(url, port) {
                    let test_url = format!("{}/v2/", base_url);

                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        self.http_client.get(&test_url),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            if (response.status_code == 200 || response.status_code == 401)
                                && self.is_registry_response(&response.body, &response.headers)
                            {
                                info!("Container registry on port {}", port);
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Container Registry on Non-Standard Port",
                                    "",
                                    &format!("Container registry running on port {}", port),
                                    &format!("Registry accessible on port {}", port),
                                    Severity::Medium,
                                    "CWE-200",
                                    5.3,
                                ));
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Registry port {} check failed: {}", port, e);
                        }
                        Err(_) => {
                            debug!("Registry port {} check timed out (3s)", port);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for container secrets exposure
    async fn test_container_secrets_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing for container secrets exposure");

        let secret_paths = vec![
            "/run/secrets/",
            "/.dockerenv",
            "/proc/self/environ",
            "/proc/1/environ",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "/.kube/config",
            "/root/.docker/config.json",
            "/home/*/.docker/config.json",
            "/etc/docker/daemon.json",
            "/etc/kubernetes/",
        ];

        for secret_path in secret_paths {
            let test_url = self.build_url(url, secret_path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && !response.body.is_empty() {
                        if let Some(secret_type) = self.detect_container_secret(&response.body) {
                            info!(
                                "Container secret exposed: {} at {}",
                                secret_type, secret_path
                            );
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Container Secret Exposure",
                                "",
                                &format!("{} exposed at {}", secret_type, secret_path),
                                &format!("Sensitive container secret accessible: {}", secret_type),
                                Severity::Critical,
                                "CWE-552",
                                9.1,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Secret path {} check failed: {}", secret_path, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn is_docker_api_response(&self, body: &str) -> bool {
        let docker_indicators = vec![
            "\"Id\":",
            "\"Image\":",
            "\"Command\":",
            "\"Created\":",
            "\"State\":",
            "\"Status\":",
            "\"ApiVersion\":",
            "\"Platform\":",
        ];

        let body_lower = body.to_lowercase();
        let mut matches = 0;

        for indicator in docker_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }

        false
    }

    fn is_kubernetes_response(&self, body: &str) -> bool {
        let k8s_indicators = vec![
            "\"kind\":",
            "\"apiVersion\":",
            "\"metadata\":",
            "\"items\":",
            "kubernetes",
            "k8s.io",
        ];

        let body_lower = body.to_lowercase();
        let mut matches = 0;

        for indicator in k8s_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }

        false
    }

    fn is_registry_response(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            if key_lower == "docker-distribution-api-version"
                || value_lower.contains("registry")
                || value_lower.contains("docker")
            {
                return true;
            }
        }

        let body_lower = body.to_lowercase();
        body_lower.contains("\"repositories\"")
            || body_lower.contains("\"name\"") && body_lower.contains("\"tags\"")
            || body_lower == "{}"
    }

    fn detect_container_secret(&self, body: &str) -> Option<String> {
        let patterns = vec![
            (r"eyJhbGciOi", "Kubernetes Service Account Token"),
            (r"-----BEGIN CERTIFICATE-----", "TLS Certificate"),
            (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
            (r"-----BEGIN PRIVATE KEY-----", "Private Key"),
            (r#""auths"\s*:"#, "Docker Registry Auth"),
            (r"DOCKER_", "Docker Environment Variable"),
            (r"KUBE_", "Kubernetes Environment Variable"),
            (r"KUBERNETES_", "Kubernetes Environment Variable"),
            (r"AWS_", "AWS Credential"),
            (r"AZURE_", "Azure Credential"),
            (r"GCP_", "GCP Credential"),
        ];

        for (pattern, secret_type) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    return Some(secret_type.to_string());
                }
            }
        }

        None
    }

    fn build_url(&self, base: &str, path: &str) -> String {
        if let Ok(parsed) = url::Url::parse(base) {
            let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if base_url.ends_with('/') && path.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else if !base_url.ends_with('/') && !path.starts_with('/') {
                format!("{}/{}", base_url, path)
            } else {
                format!("{}{}", base_url, path)
            }
        } else {
            format!("{}{}", base, path)
        }
    }

    fn extract_base_with_port(&self, url: &str, port: &str) -> Option<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return Some(format!("{}://{}:{}", parsed.scheme(), host, port));
            }
        }
        None
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
            id: format!("container_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Container Security".to_string(),
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
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Exposed Docker API" | "Exposed Docker Daemon" => {
                "1. Never expose Docker API to the internet\n\
                 2. Use TLS authentication for Docker daemon (port 2376)\n\
                 3. Disable TCP socket (unix:///var/run/docker.sock only)\n\
                 4. Implement firewall rules to restrict access\n\
                 5. Use Docker socket proxy if remote access needed\n\
                 6. Enable Docker authorization plugins\n\
                 7. Run Docker in rootless mode when possible\n\
                 8. Implement network segmentation\n\
                 9. Use Docker Swarm or Kubernetes for orchestration\n\
                 10. Regular security audits and monitoring".to_string()
            }
            "Exposed Kubernetes API" | "Exposed Kubernetes Component" => {
                "1. Never expose Kubernetes API server to the internet\n\
                 2. Use strong RBAC policies and service accounts\n\
                 3. Enable API server authentication (--anonymous-auth=false)\n\
                 4. Use admission controllers (PodSecurityPolicy, etc.)\n\
                 5. Implement network policies for pod communication\n\
                 6. Enable audit logging for all API requests\n\
                 7. Use kubectl proxy or VPN for remote access\n\
                 8. Regular security scanning with kube-bench, kube-hunter\n\
                 9. Implement secrets encryption at rest\n\
                 10. Use managed Kubernetes with security best practices".to_string()
            }
            "Exposed Container Registry" | "Container Registry Detected" => {
                "1. Require authentication for all registry access\n\
                 2. Use HTTPS/TLS for all registry connections\n\
                 3. Implement role-based access control\n\
                 4. Enable content trust and image signing\n\
                 5. Scan images for vulnerabilities before deployment\n\
                 6. Use private registries for production images\n\
                 7. Implement image retention policies\n\
                 8. Enable audit logging for registry access\n\
                 9. Use registry webhooks for security scanning\n\
                 10. Regular vulnerability scanning of stored images".to_string()
            }
            "Container Secret Exposure" => {
                "1. Never expose container secrets via HTTP\n\
                 2. Use Kubernetes secrets with encryption at rest\n\
                 3. Implement least privilege for service accounts\n\
                 4. Use external secret management (Vault, AWS Secrets Manager)\n\
                 5. Mount secrets as files, not environment variables\n\
                 6. Rotate secrets regularly\n\
                 7. Use short-lived tokens when possible\n\
                 8. Implement proper file permissions (0600)\n\
                 9. Scan for exposed secrets in CI/CD\n\
                 10. Use workload identity instead of static credentials".to_string()
            }
            _ => "Follow container security best practices (CIS Docker Benchmark, CIS Kubernetes Benchmark)".to_string(),
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
    use crate::detection_helpers::AppCharacteristics;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> ContainerScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        ContainerScanner::new(http_client)
    }

    #[test]
    fn test_is_docker_api_response() {
        let scanner = create_test_scanner();

        let docker_json =
            r#"[{"Id":"abc123","Image":"nginx:latest","Command":"nginx","Created":1234567890}]"#;
        assert!(scanner.is_docker_api_response(docker_json));

        let docker_info = r#"{"ApiVersion":"1.41","Platform":{"Name":"Docker Engine"}}"#;
        assert!(scanner.is_docker_api_response(docker_info));
    }

    #[test]
    fn test_is_kubernetes_response() {
        let scanner = create_test_scanner();

        let k8s_json = r#"{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[]}"#;
        assert!(scanner.is_kubernetes_response(k8s_json));

        let k8s_error = r#"{"kind":"Status","apiVersion":"v1","status":"Failure"}"#;
        assert!(scanner.is_kubernetes_response(k8s_error));
    }

    #[test]
    fn test_is_registry_response() {
        let scanner = create_test_scanner();
        let mut headers = std::collections::HashMap::new();

        headers.insert(
            "Docker-Distribution-Api-Version".to_string(),
            "registry/2.0".to_string(),
        );
        assert!(scanner.is_registry_response("", &headers));

        headers.clear();
        let registry_json = r#"{"repositories":["ubuntu","nginx"]}"#;
        assert!(scanner.is_registry_response(registry_json, &headers));
    }

    #[test]
    fn test_detect_container_secret() {
        let scanner = create_test_scanner();

        let k8s_token =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0...";
        assert!(scanner.detect_container_secret(k8s_token).is_some());

        let cert = "-----BEGIN CERTIFICATE-----\nMIIDHTCCA...";
        assert!(scanner.detect_container_secret(cert).is_some());

        let docker_auth = r#"{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"}}}"#;
        assert!(scanner.detect_container_secret(docker_auth).is_some());
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.is_docker_api_response("Normal web page"));
        assert!(!scanner.is_kubernetes_response("Regular JSON"));
        assert!(scanner.detect_container_secret("No secrets here").is_none());
    }

    #[test]
    fn test_extract_base_with_port() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_base_with_port("https://example.com/path", "2375"),
            Some("https://example.com:2375".to_string())
        );
    }
}
