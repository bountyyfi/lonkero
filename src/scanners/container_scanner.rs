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

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_orchestration_platform_exposure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for exposed orchestration / secrets-management platforms
    ///
    /// Each platform here has at least two specific response markers that almost never
    /// appear together on benign endpoints, so detection requires both an API-shaped
    /// path AND a body fingerprint match. This avoids false positives from JSON 404
    /// pages or generic reverse-proxy responses.
    async fn test_orchestration_platform_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing for orchestration platform exposure");

        // (endpoint, platform name, body fingerprint detector, severity, cwe, cvss)
        // Functions return true only when two or more strong markers are present.
        type Detector = fn(&str, &std::collections::HashMap<String, String>) -> bool;
        let platforms: Vec<(&str, &str, Detector, Severity, &str, f64)> = vec![
            // etcd v3 - cluster key-value store. Leaking it leaks every k8s secret.
            (
                "/version",
                "etcd KV Store",
                Self::is_etcd_response,
                Severity::Critical,
                "CWE-306",
                9.8,
            ),
            (
                "/v2/keys/?recursive=true",
                "etcd v2 KV Store",
                Self::is_etcd_response,
                Severity::Critical,
                "CWE-306",
                9.8,
            ),
            // cAdvisor - container metrics, often exposes container layout / env names.
            (
                "/api/v1.3/machine",
                "cAdvisor",
                Self::is_cadvisor_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            (
                "/api/v2.0/spec",
                "cAdvisor v2",
                Self::is_cadvisor_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            // Kubelet read-only API (default port 10255) - pods, secrets refs, host info.
            (
                "/pods",
                "Kubelet Read-Only API",
                Self::is_kubelet_response,
                Severity::Critical,
                "CWE-306",
                9.8,
            ),
            (
                "/stats/summary",
                "Kubelet Stats Summary",
                Self::is_kubelet_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            // Consul - service discovery + KV. Often hosts secrets.
            (
                "/v1/status/leader",
                "HashiCorp Consul",
                Self::is_consul_response,
                Severity::High,
                "CWE-306",
                8.6,
            ),
            (
                "/v1/kv/?recurse",
                "HashiCorp Consul KV",
                Self::is_consul_response,
                Severity::Critical,
                "CWE-306",
                9.1,
            ),
            // Vault - secrets manager. Even unsealed status is a strong signal.
            (
                "/v1/sys/seal-status",
                "HashiCorp Vault",
                Self::is_vault_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            (
                "/v1/sys/health",
                "HashiCorp Vault",
                Self::is_vault_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            // Nomad - workload scheduler.
            (
                "/v1/agent/self",
                "HashiCorp Nomad",
                Self::is_nomad_response,
                Severity::Critical,
                "CWE-306",
                9.1,
            ),
            (
                "/v1/jobs",
                "HashiCorp Nomad",
                Self::is_nomad_response,
                Severity::Critical,
                "CWE-306",
                9.1,
            ),
            // Portainer - container management UI.
            (
                "/api/status",
                "Portainer",
                Self::is_portainer_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            (
                "/api/users/admin/check",
                "Portainer (admin init)",
                Self::is_portainer_response,
                Severity::Critical,
                "CWE-306",
                9.8,
            ),
            // Rancher - K8s management.
            (
                "/v3/clusters",
                "Rancher",
                Self::is_rancher_response,
                Severity::Critical,
                "CWE-306",
                9.1,
            ),
            (
                "/ping",
                "Rancher",
                Self::is_rancher_response,
                Severity::Medium,
                "CWE-200",
                5.3,
            ),
            // Traefik dashboard - reverse-proxy config (backends, routers).
            (
                "/api/rawdata",
                "Traefik Dashboard",
                Self::is_traefik_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            (
                "/api/version",
                "Traefik Dashboard",
                Self::is_traefik_response,
                Severity::Medium,
                "CWE-200",
                5.3,
            ),
            // ArgoCD - GitOps controller. Often holds cluster credentials.
            (
                "/api/v1/session/userinfo",
                "ArgoCD",
                Self::is_argocd_response,
                Severity::High,
                "CWE-200",
                7.5,
            ),
            (
                "/api/version",
                "ArgoCD",
                Self::is_argocd_response,
                Severity::Medium,
                "CWE-200",
                5.3,
            ),
        ];

        for (endpoint, platform, detector, severity, cwe, cvss) in platforms {
            tests_run += 1;
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Accept 200 (open) or 401/403 (auth required) only when the body/headers
                    // unambiguously identify the platform. 401/403 alone is downgraded.
                    let body_match = detector(&response.body, &response.headers);
                    if response.status_code == 200 && body_match {
                        info!("Exposed {} detected at {}", platform, endpoint);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("Exposed {} API", platform),
                            "",
                            &format!(
                                "{} API is publicly accessible without authentication",
                                platform
                            ),
                            &format!("{} accessible at {}", platform, endpoint),
                            severity,
                            cwe,
                            cvss,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }

                    if (response.status_code == 401 || response.status_code == 403) && body_match {
                        info!("{} detected (auth required) at {}", platform, endpoint);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("{} API Detected (Auth Required)", platform),
                            "",
                            &format!(
                                "{} API is exposed at {} but requires authentication",
                                platform, endpoint
                            ),
                            &format!("{} responding with auth challenge at {}", platform, endpoint),
                            Severity::Low,
                            "CWE-200",
                            3.7,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Platform probe {} failed: {}", endpoint, e);
                }
            }
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
                            // Require Docker-specific response, not bare "OK"
                            if response.status_code == 200
                                && (response.body.contains("Docker")
                                    || response.body.contains("Api-Version")
                                    || response.body.contains("docker"))
                            {
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
                            // Require K8s-specific response, not bare "ok"
                            if response.status_code == 200
                                && (response.body.to_lowercase().contains("kubernetes")
                                    || response.body.contains("kubelet")
                                    || response.body.contains("apiVersion"))
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

    /// etcd /version returns {"etcdserver":"...","etcdcluster":"..."}.
    /// /v2/keys responses contain "node" + "createdIndex"/"modifiedIndex".
    /// Either combination is platform-specific.
    fn is_etcd_response(body: &str, _headers: &std::collections::HashMap<String, String>) -> bool {
        (body.contains("\"etcdserver\"") && body.contains("\"etcdcluster\""))
            || (body.contains("\"createdIndex\"") && body.contains("\"modifiedIndex\""))
            || (body.contains("\"action\"") && body.contains("\"node\"") && body.contains("\"key\""))
    }

    /// cAdvisor /api/v1.3/machine returns rich machine info with these unique keys.
    fn is_cadvisor_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        let must_have = ["\"machine_id\"", "\"num_cores\"", "\"memory_capacity\""];
        must_have.iter().filter(|m| body.contains(*m)).count() >= 2
    }

    /// Kubelet /pods returns a PodList; /stats/summary has very specific fields.
    fn is_kubelet_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        if body.contains("\"kind\":\"PodList\"") || body.contains("\"kind\": \"PodList\"") {
            return true;
        }
        // /stats/summary: node + pods + cpu + memory in same response
        body.contains("\"nodeName\"")
            && body.contains("\"pods\"")
            && (body.contains("\"cpu\"") || body.contains("\"memory\""))
    }

    /// Consul advertises itself via header AND specific JSON shapes.
    fn is_consul_response(body: &str, headers: &std::collections::HashMap<String, String>) -> bool {
        for (k, _v) in headers {
            if k.to_lowercase() == "x-consul-index"
                || k.to_lowercase() == "x-consul-knownleader"
                || k.to_lowercase() == "x-consul-lastcontact"
            {
                return true;
            }
        }
        // /v1/status/leader returns a quoted "host:8300" string.
        let trimmed = body.trim();
        if trimmed.starts_with('"')
            && trimmed.ends_with(":8300\"")
            && trimmed.len() > 3
            && trimmed.len() < 64
        {
            return true;
        }
        // KV recurse returns array of objects with these exact keys.
        body.contains("\"LockIndex\"")
            && body.contains("\"ModifyIndex\"")
            && body.contains("\"CreateIndex\"")
    }

    /// Vault has a stable seal-status / health JSON shape.
    fn is_vault_response(body: &str, headers: &std::collections::HashMap<String, String>) -> bool {
        for (k, _v) in headers {
            if k.to_lowercase() == "x-vault-server-version"
                || k.to_lowercase() == "x-vault-cluster"
            {
                return true;
            }
        }
        // seal-status: {"type":"...","initialized":bool,"sealed":bool,"t":N,"n":N,...}
        let seal_keys = ["\"sealed\"", "\"initialized\"", "\"version\""];
        if seal_keys.iter().filter(|k| body.contains(*k)).count() >= 2
            && (body.contains("\"cluster_name\"") || body.contains("\"cluster_id\""))
        {
            return true;
        }
        false
    }

    /// Nomad /v1/agent/self has a deeply nested config with these unique markers.
    fn is_nomad_response(body: &str, _headers: &std::collections::HashMap<String, String>) -> bool {
        if body.contains("\"NomadConfig\"") || body.contains("\"member\"") && body.contains("\"Nomad\"") {
            return true;
        }
        // /v1/jobs returns an array of objects with these specific keys together.
        body.contains("\"JobModifyIndex\"")
            && body.contains("\"Datacenters\"")
            && body.contains("\"TaskGroups\"")
    }

    /// Portainer ships a distinct API response shape and admin-init endpoint.
    fn is_portainer_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        // /api/status: {"Version":"...","Edition":"CE",...,"InstanceID":"..."}
        if body.contains("\"Edition\"")
            && body.contains("\"InstanceID\"")
            && body.contains("\"Version\"")
        {
            return true;
        }
        // /api/users/admin/check: 404 with this exact body when admin already exists,
        // 204 when admin not yet initialised (then the system is takeover-ready).
        body.contains("\"message\":\"No administrator account found\"")
            || body.contains("admin user is not yet initialized")
    }

    /// Rancher /v3/clusters uses a Cattle-style envelope with a recognisable schema URL.
    fn is_rancher_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        if body.contains("\"type\":\"collection\"") && body.contains("rancher") {
            return true;
        }
        // /ping endpoint returns literally "pong" - but only treat as Rancher when paired
        // with a Rancher-specific server/header signature (handled by caller via 401/403
        // semantics in dashboards). The kv-store-only test is intentionally strict here.
        body.contains("\"baseType\":\"cluster\"")
    }

    /// Traefik dashboard API responses include specific fields.
    fn is_traefik_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        // /api/rawdata returns routers/services/middlewares as top-level keys.
        if body.contains("\"routers\"")
            && body.contains("\"services\"")
            && body.contains("\"middlewares\"")
        {
            return true;
        }
        // /api/version returns {"Version":"...","Codename":"...","startDate":"..."}
        body.contains("\"Codename\"") && body.contains("\"Version\"")
    }

    /// ArgoCD has a distinct API namespace shape.
    fn is_argocd_response(
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        // /api/version: {"Version":"v...","BuildDate":"...","GitCommit":"...","KustomizeVersion":"..."}
        if body.contains("\"KustomizeVersion\"")
            || body.contains("\"HelmVersion\"")
            || body.contains("\"KubectlVersion\"")
        {
            return true;
        }
        // /api/v1/session/userinfo: anonymous = {"loggedIn":false,...}
        body.contains("\"loggedIn\"") && body.contains("\"username\"")
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
            t if t.contains("etcd") => {
                "1. Bind etcd to loopback or a private subnet only\n\
                 2. Require client TLS certificates (--client-cert-auth)\n\
                 3. Enable peer TLS between cluster members\n\
                 4. Treat any etcd exposure as full Kubernetes cluster compromise\n\
                 5. Rotate every secret stored in etcd after disclosure".to_string()
            }
            t if t.contains("cAdvisor") => {
                "1. Restrict cAdvisor (default port 8080/4194) to monitoring networks\n\
                 2. Front cAdvisor with authenticating reverse proxy\n\
                 3. Disable on production nodes if metrics flow through Prometheus instead".to_string()
            }
            t if t.contains("Kubelet") => {
                "1. Disable the read-only kubelet port (--read-only-port=0)\n\
                 2. Require authentication on the kubelet API (--anonymous-auth=false)\n\
                 3. Restrict kubelet ports (10250, 10255) at the host firewall\n\
                 4. Enable kubelet authorization mode Webhook".to_string()
            }
            t if t.contains("Consul") => {
                "1. Enable Consul ACLs (acl.enabled = true, default_policy = \"deny\")\n\
                 2. Require TLS on HTTP API (ports_https + verify_incoming)\n\
                 3. Restrict the HTTP API to internal networks only\n\
                 4. Rotate every secret stored in Consul KV after disclosure".to_string()
            }
            t if t.contains("Vault") => {
                "1. Front Vault with an authenticating reverse proxy\n\
                 2. Restrict the API to known clients via firewall / mTLS\n\
                 3. Audit access logs for unusual seal-status / login probing\n\
                 4. Even a sealed Vault leaks version info — keep the binary patched".to_string()
            }
            t if t.contains("Nomad") => {
                "1. Enable Nomad ACLs and require tokens for all API calls\n\
                 2. Bind the HTTP API to the management network only\n\
                 3. Treat exposed Nomad as remote code execution: jobs can run arbitrary commands".to_string()
            }
            t if t.contains("Portainer") => {
                "1. Never expose Portainer to the public internet without SSO/2FA\n\
                 2. If the admin-init endpoint is reachable, an attacker can claim admin — \
                 initialise Portainer immediately and disable public access\n\
                 3. Place Portainer behind a VPN or authenticating reverse proxy".to_string()
            }
            t if t.contains("Rancher") => {
                "1. Restrict Rancher UI/API to corporate VPN\n\
                 2. Enforce SSO + 2FA for all users\n\
                 3. Rotate cluster registration tokens after disclosure".to_string()
            }
            t if t.contains("Traefik") => {
                "1. Disable the Traefik dashboard in production (api.dashboard = false) or \
                 restrict it with basic-auth + IP allowlist\n\
                 2. Never expose api.insecure = true outside localhost\n\
                 3. Treat the rawdata endpoint as a full reverse-proxy map disclosure".to_string()
            }
            t if t.contains("ArgoCD") => {
                "1. Front ArgoCD with SSO and disable anonymous access\n\
                 2. Restrict the API server to internal networks\n\
                 3. Rotate cluster credentials managed by ArgoCD after disclosure".to_string()
            }
            _ => "Follow container security best practices (CIS Docker Benchmark, CIS Kubernetes Benchmark)".to_string(),
        }
    }
}

mod uuid {
    use rand::RngExt;

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

    #[test]
    fn test_is_etcd_response() {
        let headers = std::collections::HashMap::new();
        let v3_version = r#"{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}"#;
        assert!(ContainerScanner::is_etcd_response(v3_version, &headers));

        let v2_get = r#"{"action":"get","node":{"key":"/foo","value":"bar","createdIndex":4,"modifiedIndex":4}}"#;
        assert!(ContainerScanner::is_etcd_response(v2_get, &headers));

        assert!(!ContainerScanner::is_etcd_response("Not Found", &headers));
        // A bare JSON 404 must not trigger.
        assert!(!ContainerScanner::is_etcd_response(
            r#"{"error":"not found"}"#,
            &headers
        ));
    }

    #[test]
    fn test_is_cadvisor_response() {
        let headers = std::collections::HashMap::new();
        let machine = r#"{"num_cores":8,"cpu_frequency_khz":2400000,"memory_capacity":16000000000,"machine_id":"abc123"}"#;
        assert!(ContainerScanner::is_cadvisor_response(machine, &headers));

        // Only one marker - not enough.
        assert!(!ContainerScanner::is_cadvisor_response(
            r#"{"machine_id":"abc"}"#,
            &headers
        ));
    }

    #[test]
    fn test_is_kubelet_response() {
        let headers = std::collections::HashMap::new();
        let pods = r#"{"kind":"PodList","apiVersion":"v1","items":[]}"#;
        assert!(ContainerScanner::is_kubelet_response(pods, &headers));

        let stats = r#"{"node":{"nodeName":"node1","cpu":{},"memory":{},"pods":[]}}"#;
        assert!(ContainerScanner::is_kubelet_response(stats, &headers));

        assert!(!ContainerScanner::is_kubelet_response("nothing here", &headers));
    }

    #[test]
    fn test_is_consul_response() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Consul-Index".to_string(), "5".to_string());
        assert!(ContainerScanner::is_consul_response("anything", &headers));

        let headers = std::collections::HashMap::new();
        let leader = r#""10.0.0.1:8300""#;
        assert!(ContainerScanner::is_consul_response(leader, &headers));

        let kv = r#"[{"LockIndex":0,"Key":"foo","Flags":0,"Value":"YmFy","CreateIndex":5,"ModifyIndex":5}]"#;
        assert!(ContainerScanner::is_consul_response(kv, &headers));

        assert!(!ContainerScanner::is_consul_response("plain text", &headers));
    }

    #[test]
    fn test_is_vault_response() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Vault-Server-Version".to_string(), "1.15.0".to_string());
        assert!(ContainerScanner::is_vault_response("body", &headers));

        let headers = std::collections::HashMap::new();
        let seal = r#"{"type":"shamir","initialized":true,"sealed":false,"t":3,"n":5,"version":"1.15.0","cluster_name":"vault-cluster-abc"}"#;
        assert!(ContainerScanner::is_vault_response(seal, &headers));

        // Missing cluster_name - reject to avoid generic FP.
        let weak = r#"{"sealed":false,"initialized":true,"version":"1.0"}"#;
        assert!(!ContainerScanner::is_vault_response(weak, &headers));
    }

    #[test]
    fn test_is_nomad_response() {
        let headers = std::collections::HashMap::new();
        let agent = r#"{"member":{"Name":"node1","Tags":{}},"NomadConfig":{}}"#;
        assert!(ContainerScanner::is_nomad_response(agent, &headers));

        let jobs = r#"[{"ID":"web","Datacenters":["dc1"],"TaskGroups":[],"JobModifyIndex":5}]"#;
        assert!(ContainerScanner::is_nomad_response(jobs, &headers));

        assert!(!ContainerScanner::is_nomad_response("{}", &headers));
    }

    #[test]
    fn test_is_portainer_response() {
        let headers = std::collections::HashMap::new();
        let status = r#"{"Version":"2.19.0","Edition":"CE","InstanceID":"abc-123"}"#;
        assert!(ContainerScanner::is_portainer_response(status, &headers));

        let admin_uninit = r#"{"message":"No administrator account found"}"#;
        assert!(ContainerScanner::is_portainer_response(admin_uninit, &headers));

        assert!(!ContainerScanner::is_portainer_response(
            r#"{"Version":"1.0"}"#,
            &headers
        ));
    }

    #[test]
    fn test_is_rancher_response() {
        let headers = std::collections::HashMap::new();
        let collection = r#"{"type":"collection","data":[],"links":{"self":"https://rancher.example/v3/clusters"}}"#;
        assert!(ContainerScanner::is_rancher_response(collection, &headers));

        assert!(!ContainerScanner::is_rancher_response("pong", &headers));
    }

    #[test]
    fn test_is_traefik_response() {
        let headers = std::collections::HashMap::new();
        let rawdata = r#"{"routers":{},"services":{},"middlewares":{}}"#;
        assert!(ContainerScanner::is_traefik_response(rawdata, &headers));

        let version = r#"{"Version":"2.10.0","Codename":"saintnectaire","startDate":"2024-01-01"}"#;
        assert!(ContainerScanner::is_traefik_response(version, &headers));

        // Lone "Version" must not trigger.
        assert!(!ContainerScanner::is_traefik_response(
            r#"{"Version":"1.0"}"#,
            &headers
        ));
    }

    #[test]
    fn test_is_argocd_response() {
        let headers = std::collections::HashMap::new();
        let version = r#"{"Version":"v2.8.0","BuildDate":"2024-01-01","KustomizeVersion":"v5.0.0"}"#;
        assert!(ContainerScanner::is_argocd_response(version, &headers));

        let userinfo = r#"{"loggedIn":false,"username":""}"#;
        assert!(ContainerScanner::is_argocd_response(userinfo, &headers));

        assert!(!ContainerScanner::is_argocd_response(
            r#"{"Version":"1.0"}"#,
            &headers
        ));
    }
}
