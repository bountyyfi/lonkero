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
            let (vulns, tests) = self.test_orchestration_dashboards_exposure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for exposed orchestration/registry management dashboards.
    ///
    /// Each entry is `(path, product, body_signature, severity, cvss)`. The
    /// body_signature must appear in the response body for the finding to fire
    /// — generic 200s never trigger.
    async fn test_orchestration_dashboards_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        debug!("Testing for orchestration dashboard exposure");

        let probes: Vec<(&str, &str, &[&str], Severity, f64)> = vec![
            // Portainer — `/api/status` returns JSON with Version. Anonymous
            // access on /api/endpoints means full container control.
            (
                "/api/status",
                "Portainer",
                &["\"Version\"", "Portainer"],
                Severity::High,
                7.5,
            ),
            (
                "/api/endpoints",
                "Portainer (unauthenticated endpoints)",
                &["\"PublicURL\"", "\"EndpointType\""],
                Severity::Critical,
                9.8,
            ),
            // Rancher — `/v3/clusters` returns JSON with type=collection.
            (
                "/v3/clusters",
                "Rancher",
                &["\"type\":\"collection\"", "\"resourceType\":\"cluster\""],
                Severity::High,
                7.5,
            ),
            (
                "/v3/users",
                "Rancher (unauthenticated user list)",
                &["\"type\":\"collection\"", "\"resourceType\":\"user\""],
                Severity::Critical,
                9.1,
            ),
            // Harbor — `/api/v2.0/systeminfo` is unauthenticated by default and
            // leaks harbor_version + registry URL.
            (
                "/api/v2.0/systeminfo",
                "Harbor Registry",
                &["\"harbor_version\""],
                Severity::Medium,
                5.3,
            ),
            (
                "/api/v2.0/projects",
                "Harbor Projects",
                &["\"project_id\"", "\"repo_count\""],
                Severity::High,
                7.5,
            ),
            // Quay container registry
            (
                "/api/v1/discovery",
                "Quay Registry",
                &["\"paths\"", "\"swagger\""],
                Severity::Medium,
                5.3,
            ),
            // JFrog Artifactory
            (
                "/artifactory/api/system/ping",
                "JFrog Artifactory",
                &["OK"],
                Severity::Low,
                3.7,
            ),
            (
                "/artifactory/api/repositories",
                "JFrog Artifactory Repositories",
                &["\"key\"", "\"packageType\""],
                Severity::High,
                7.5,
            ),
            // Sonatype Nexus
            (
                "/service/rest/v1/status",
                "Sonatype Nexus",
                &["NexusRM"],
                Severity::Low,
                3.7,
            ),
            (
                "/service/rest/v1/repositories",
                "Sonatype Nexus Repositories",
                &["\"format\"", "\"type\""],
                Severity::Medium,
                5.3,
            ),
            // ArgoCD — `/api/version` always anonymous; `/api/v1/applications`
            // without auth lets attackers read GitOps deploy specs.
            (
                "/api/version",
                "ArgoCD",
                &["\"BuildDate\"", "\"GitCommit\""],
                Severity::Low,
                3.7,
            ),
            (
                "/api/v1/applications",
                "ArgoCD Applications",
                &["\"argoproj.io\"", "\"Application\""],
                Severity::Critical,
                9.1,
            ),
            // Kubernetes Dashboard
            (
                "/api/v1/login/status",
                "Kubernetes Dashboard",
                &["\"tokenPresent\"", "\"headerPresent\""],
                Severity::High,
                7.5,
            ),
            // HashiCorp Vault — seal status leak is informational; an unsealed
            // Vault with no auth required would surface secrets via /v1/sys.
            (
                "/v1/sys/seal-status",
                "HashiCorp Vault",
                &["\"sealed\"", "\"cluster_name\""],
                Severity::Medium,
                5.3,
            ),
            // HashiCorp Consul — `/v1/agent/self` exposes cluster config.
            (
                "/v1/agent/self",
                "HashiCorp Consul",
                &["\"Config\"", "\"NodeName\""],
                Severity::High,
                7.5,
            ),
            (
                "/v1/catalog/services",
                "HashiCorp Consul Services",
                &["\"consul\""],
                Severity::Medium,
                5.3,
            ),
            // Traefik dashboard
            (
                "/api/overview",
                "Traefik Dashboard",
                &["\"http\"", "\"routers\"", "\"middlewares\""],
                Severity::Medium,
                5.3,
            ),
            // Spinnaker Gate
            (
                "/gate/applications",
                "Spinnaker",
                &["\"accounts\"", "\"cloudProviders\""],
                Severity::High,
                7.5,
            ),
            // Drone CI
            (
                "/api/info",
                "Drone CI",
                &["\"version\"", "\"runner\""],
                Severity::Medium,
                5.3,
            ),
        ];
        let tests_run = probes.len();

        for (path, product, signatures, severity, cvss) in probes {
            let test_url = self.build_url(url, path);

            let response = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Dashboard probe {} failed: {}", path, e);
                    continue;
                }
            };

            if response.status_code != 200 || response.body.is_empty() {
                continue;
            }

            // Require ALL configured signatures to appear in the body. Single
            // generic tokens (e.g. just "Version") are too weak on their own.
            let body = &response.body;
            if !signatures.iter().all(|sig| body.contains(sig)) {
                continue;
            }

            info!("Exposed {} dashboard at {}", product, path);
            let vuln_type = "Exposed Orchestration Dashboard";
            vulnerabilities.push(self.create_vulnerability(
                url,
                vuln_type,
                "",
                &format!(
                    "{} management endpoint accessible without authentication at {}",
                    product, path
                ),
                &format!("{} response signature matched at {}", product, path),
                severity,
                "CWE-306",
                cvss,
            ));
            break;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for exposed Docker API
    async fn test_docker_api_exposure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        debug!("Testing for Docker API exposure");

        let docker_endpoints = vec![
            ("/v1.40/containers/json", "Docker API v1.40"),
            ("/v1.41/containers/json", "Docker API v1.41"),
            ("/v1.42/containers/json", "Docker API v1.42"),
            ("/v1.43/containers/json", "Docker API v1.43"),
            ("/v1.44/containers/json", "Docker API v1.44"),
            ("/v1.45/containers/json", "Docker API v1.45"),
            ("/v1.46/containers/json", "Docker API v1.46"),
            ("/v1.47/containers/json", "Docker API v1.47"),
            ("/v1.48/containers/json", "Docker API v1.48"),
            ("/containers/json", "Docker API"),
            ("/containers/json?all=1", "Docker API (all containers)"),
            ("/images/json", "Docker Images API"),
            ("/info", "Docker Info"),
            ("/version", "Docker Version"),
            ("/_ping", "Docker Ping"),
            ("/events", "Docker Events"),
            ("/system/info", "Docker System Info"),
            ("/system/df", "Docker System DF"),
            ("/networks", "Docker Networks"),
            ("/volumes", "Docker Volumes"),
            ("/services", "Docker Swarm Services"),
            ("/secrets", "Docker Swarm Secrets"),
            ("/configs", "Docker Swarm Configs"),
            ("/nodes", "Docker Swarm Nodes"),
            ("/swarm", "Docker Swarm"),
            ("/tasks", "Docker Swarm Tasks"),
            ("/plugins", "Docker Plugins"),
        ];
        let tests_run = docker_endpoints.len();

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

        debug!("Testing for Kubernetes API exposure");

        let k8s_endpoints = vec![
            ("/api/v1", "Kubernetes API"),
            ("/api/v1/namespaces", "K8s Namespaces"),
            ("/api/v1/pods", "K8s Pods"),
            ("/api/v1/secrets", "K8s Secrets"),
            ("/api/v1/configmaps", "K8s ConfigMaps"),
            ("/api/v1/services", "K8s Services"),
            ("/api/v1/serviceaccounts", "K8s ServiceAccounts"),
            ("/api/v1/persistentvolumes", "K8s PersistentVolumes"),
            ("/api/v1/persistentvolumeclaims", "K8s PVCs"),
            ("/api/v1/nodes", "K8s Nodes"),
            ("/api/v1/endpoints", "K8s Endpoints"),
            ("/api/v1/namespaces/kube-system/secrets", "K8s kube-system Secrets"),
            ("/api/v1/namespaces/default/secrets", "K8s default Secrets"),
            ("/apis/apps/v1/deployments", "K8s Deployments"),
            ("/apis/apps/v1/daemonsets", "K8s DaemonSets"),
            ("/apis/apps/v1/statefulsets", "K8s StatefulSets"),
            ("/apis/apps/v1/replicasets", "K8s ReplicaSets"),
            ("/apis/batch/v1/jobs", "K8s Jobs"),
            ("/apis/batch/v1/cronjobs", "K8s CronJobs"),
            ("/apis/networking.k8s.io/v1/ingresses", "K8s Ingresses"),
            ("/apis/networking.k8s.io/v1/networkpolicies", "K8s NetworkPolicies"),
            ("/apis/rbac.authorization.k8s.io/v1/clusterroles", "K8s ClusterRoles"),
            ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "K8s ClusterRoleBindings"),
            ("/apis/rbac.authorization.k8s.io/v1/roles", "K8s Roles"),
            ("/apis/rbac.authorization.k8s.io/v1/rolebindings", "K8s RoleBindings"),
            ("/apis/storage.k8s.io/v1/storageclasses", "K8s StorageClasses"),
            ("/apis/policy/v1/poddisruptionbudgets", "K8s PodDisruptionBudgets"),
            ("/apis", "K8s APIs"),
            ("/healthz", "K8s Health"),
            ("/livez", "K8s Liveness"),
            ("/readyz", "K8s Readiness"),
            ("/version", "K8s Version"),
            ("/metrics", "K8s Metrics"),
            ("/metrics/cadvisor", "Kubelet cAdvisor Metrics"),
            ("/metrics/resource", "Kubelet Resource Metrics"),
            ("/stats/summary", "Kubelet Stats Summary"),
            ("/pods", "Kubelet Pods List"),
            ("/runningpods/", "Kubelet Running Pods"),
            ("/configz", "Kubelet Config"),
            ("/swagger.json", "K8s Swagger"),
            ("/openapi/v2", "K8s OpenAPI v2"),
            ("/openapi/v3", "K8s OpenAPI v3"),
        ];
        let tests_run = k8s_endpoints.len();

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

        debug!("Testing for container registry exposure");

        let registry_endpoints = vec![
            ("/v2/", "Docker Registry v2"),
            ("/v2/_catalog", "Registry Catalog"),
            ("/v2/_catalog?n=1000", "Registry Catalog (paginated)"),
            ("/v2/library/", "Registry Library"),
            ("/v1/repositories/", "Registry Repositories"),
            ("/v1/_ping", "Registry Ping"),
            ("/v1/search", "Registry Search"),
            ("/jwt/auth?service=container_registry&scope=registry:catalog:*", "GitLab Container Registry JWT"),
        ];
        let tests_run = registry_endpoints.len();

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

        debug!("Testing for container secrets exposure");

        let secret_paths = vec![
            "/run/secrets/",
            "/.dockerenv",
            "/proc/self/environ",
            "/proc/1/environ",
            "/proc/self/status",
            "/proc/self/cgroup",
            "/proc/self/mountinfo",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "/var/run/secrets/azure/tokens/azure-identity-token",
            "/var/run/secrets/tokens/vault-token",
            "/var/run/secrets/openshift.io/serviceaccount/token",
            "/var/run/docker.sock",
            "/var/lib/kubelet/config.yaml",
            "/var/lib/kubelet/kubeconfig",
            "/var/lib/kubelet/pki/kubelet-client-current.pem",
            "/etc/kubernetes/admin.conf",
            "/etc/kubernetes/kubelet.conf",
            "/etc/kubernetes/controller-manager.conf",
            "/etc/kubernetes/scheduler.conf",
            "/etc/kubernetes/manifests/etcd.yaml",
            "/etc/kubernetes/manifests/kube-apiserver.yaml",
            "/etc/kubernetes/pki/ca.crt",
            "/etc/kubernetes/pki/apiserver.key",
            "/etc/kubernetes/pki/etcd/server.key",
            "/etc/kubernetes/",
            "/.kube/config",
            "/root/.docker/config.json",
            "/root/.config/containers/auth.json",
            "/root/.dockercfg",
            "/home/*/.docker/config.json",
            "/etc/docker/daemon.json",
            "/etc/containerd/config.toml",
            "/etc/crio/crio.conf",
            "/etc/rancher/k3s/k3s.yaml",
            "/etc/rancher/rke2/rke2.yaml",
        ];
        let tests_run = secret_paths.len();

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
            (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
            (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key"),
            (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
            (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key"),
            (r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "Encrypted Private Key"),
            (r#""auths"\s*:"#, "Docker Registry Auth"),
            (r"DOCKER_", "Docker Environment Variable"),
            (r"KUBE_", "Kubernetes Environment Variable"),
            (r"KUBERNETES_", "Kubernetes Environment Variable"),
            (r"AWS_", "AWS Credential"),
            (r"AZURE_", "Azure Credential"),
            (r"GCP_", "GCP Credential"),
            (r"\$ANSIBLE_VAULT;1\.[12];AES256", "Ansible Vault"),
            (r"hvs\.[A-Za-z0-9_-]{20,}", "HashiCorp Vault Token"),
            (r"(?m)^kind:\s*KubeletConfiguration", "Kubelet Configuration"),
            (r"(?m)^kind:\s*Config(?:$|\s)", "Kubeconfig File"),
            (r"(?m)^kind:\s*InitConfiguration", "kubeadm Init Configuration"),
            (r"(?m)^kind:\s*ClusterConfiguration", "kubeadm Cluster Configuration"),
            (r"(?m)^current-context:\s*\S", "Kubeconfig (current-context)"),
            (r#""client-certificate-data"\s*:"#, "Kubeconfig Client Certificate"),
            (r#""client-key-data"\s*:"#, "Kubeconfig Client Key"),
            (r"client-key-data:\s*[A-Za-z0-9+/=]{40,}", "Kubeconfig Client Key (YAML)"),
            (r#"command:\s*\[?\s*"?kube-apiserver"?"#, "kube-apiserver Manifest"),
            (r#"--etcd-keyfile=|--etcd-certfile="#, "etcd TLS Configuration"),
            (r#"--service-account-key-file="#, "kube-apiserver Service Account Key"),
            (r#"\[plugins\."io\.containerd\."#, "Containerd Configuration"),
            (r#"(?m)^\[crio\.runtime\]"#, "CRI-O Runtime Configuration"),
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
            "Exposed Orchestration Dashboard" => {
                "1. Require authentication on every management API endpoint\n\
                 2. Place dashboards behind a VPN, bastion, or zero-trust proxy\n\
                 3. Disable anonymous read APIs (Portainer endpoints, Rancher v3, Harbor systeminfo, ArgoCD)\n\
                 4. Bind management UIs to localhost or an internal interface only\n\
                 5. Enable SSO/OIDC with MFA for operator accounts\n\
                 6. Rotate any tokens or kubeconfigs that may have been exposed\n\
                 7. Enable audit logging on the management plane\n\
                 8. Apply network policies / security groups restricting source IPs\n\
                 9. Patch to the latest version — many of these have CVEs for older releases\n\
                 10. Review CIS benchmarks for the specific platform (Rancher/Harbor/ArgoCD/Vault)".to_string()
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
}
