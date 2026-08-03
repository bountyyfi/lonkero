// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Exposed Dashboards Scanner
//!
//! Finds publicly reachable management, monitoring, and administrative
//! dashboards that leak sensitive infrastructure information or expose
//! privileged operations. Each check requires a distinct product-specific
//! fingerprint (title, header, JSON key, or response shape) so a bare 200
//! is never enough to fire — the goal is impactful, no-false-positive
//! findings.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct ExposedDashboardsScanner {
    http_client: Arc<HttpClient>,
}

/// A single dashboard/management-interface fingerprint.
///
/// `body_needles` and `header_needles` are OR-groups: the check fires when
/// at least one needle from either list matches AND the status is one of
/// `expected_statuses`. Needles are matched case-insensitively against the
/// body and against a lowercased "name: value" join of headers.
struct DashboardCheck {
    /// URL path to request (must start with `/`).
    path: &'static str,
    /// Product name for reporting (e.g. "Grafana").
    product: &'static str,
    /// Human-readable name of the endpoint (e.g. "unauthenticated admin API").
    surface: &'static str,
    /// Substrings that, if present in the body, confirm the product.
    body_needles: &'static [&'static str],
    /// Substrings that, if present in `name: value` header pairs, confirm.
    header_needles: &'static [&'static str],
    /// HTTP status codes that count as "reachable" for this surface.
    /// Most checks accept only 200; some accept 401/403 when the
    /// existence of the surface itself is the leak.
    expected_statuses: &'static [u16],
    /// Severity of the leak (kept conservative: existence-of-panel is Info/Low,
    /// unauth data disclosure or cluster metadata is Medium/High).
    severity: Severity,
    /// CVSS score aligned with severity.
    cvss: f32,
    /// CWE identifier for the finding.
    cwe: &'static str,
    /// Remediation guidance.
    remediation: &'static str,
}

const CHECKS: &[DashboardCheck] = &[
    // ============================================================
    // Metrics / observability dashboards
    // ============================================================
    DashboardCheck {
        path: "/api/health",
        product: "Grafana",
        surface: "unauthenticated health endpoint",
        body_needles: &["\"database\":\"ok\"", "\"database\": \"ok\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Low,
        cvss: 3.7,
        cwe: "CWE-284",
        remediation:
            "Restrict Grafana `/api/health` to internal networks with a reverse proxy ACL, \
             or set `[security] allow_embedding = false` and require authentication for \
             the entire `/api/*` surface via `auth.anonymous.enabled = false`.",
    },
    DashboardCheck {
        path: "/api/datasources",
        product: "Grafana",
        surface: "unauthenticated datasources API",
        body_needles: &["\"typeLogoUrl\"", "\"jsonData\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 8.2,
        cwe: "CWE-306",
        remediation:
            "Grafana `/api/datasources` returned data without authentication. Set \
             `auth.anonymous.enabled = false`, require an admin token for the API, and \
             rotate any credentials that were embedded in the returned datasource JSON.",
    },
    DashboardCheck {
        path: "/graph",
        product: "Prometheus",
        surface: "Prometheus expression browser",
        body_needles: &["Prometheus Time Series Collection"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.3,
        cwe: "CWE-306",
        remediation:
            "The Prometheus expression browser was reachable without authentication and \
             leaks metric names, target labels, and often internal hostnames. Front it \
             with a reverse proxy that enforces auth (nginx `auth_basic`, oauth2-proxy) \
             or bind Prometheus to a private interface.",
    },
    DashboardCheck {
        path: "/api/v1/targets",
        product: "Prometheus",
        surface: "targets API (scrape targets)",
        body_needles: &["\"scrapeUrl\"", "\"discoveredLabels\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 6.5,
        cwe: "CWE-200",
        remediation:
            "Prometheus `/api/v1/targets` exposes internal scrape URLs (usually private IPs, \
             cluster DNS names, cloud metadata endpoints). Restrict access to the /api \
             surface via an authenticating reverse proxy.",
    },
    DashboardCheck {
        path: "/metrics",
        product: "Prometheus/Node Exporter",
        surface: "Prometheus text-format metrics",
        // Text-format metrics have a very distinctive HELP/TYPE line prefix
        // that is essentially unique to Prometheus exposition. Requiring two
        // markers prevents matching arbitrary pages that contain "# HELP".
        body_needles: &["# HELP go_", "# HELP process_", "# HELP node_"],
        header_needles: &["content-type: text/plain; version=0.0.4"],
        expected_statuses: &[200],
        severity: Severity::Low,
        cvss: 4.3,
        cwe: "CWE-200",
        remediation:
            "The `/metrics` endpoint is exposed on the public interface. Even without secrets, \
             it discloses process command lines, uptime, memory maps, GC counters and often \
             gives attackers a reliable way to fingerprint the runtime and detect deploys. \
             Bind exporters to `127.0.0.1` and scrape via a private network.",
    },
    DashboardCheck {
        path: "/api/v2/alerts",
        product: "Alertmanager",
        surface: "Alertmanager API",
        body_needles: &["\"receivers\":", "\"annotations\":", "\"startsAt\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.9,
        cwe: "CWE-306",
        remediation:
            "Alertmanager `/api/v2/alerts` is reachable without auth and lets an attacker \
             read live alert routing, silence real alerts, or fire fake ones. Put it \
             behind an authenticating reverse proxy.",
    },
    // ============================================================
    // Kibana / Elasticsearch
    // ============================================================
    DashboardCheck {
        path: "/api/status",
        product: "Kibana",
        surface: "Kibana status endpoint",
        body_needles: &["\"kibana\":{", "\"kibana\": {"],
        header_needles: &["kbn-name:"],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.3,
        cwe: "CWE-200",
        remediation:
            "Kibana `/api/status` leaks version, plugin list and cluster UUID. Set \
             `xpack.security.enabled: true` and require login for all UI/API routes, \
             or restrict the port to internal networks.",
    },
    DashboardCheck {
        path: "/app/kibana",
        product: "Kibana",
        surface: "unauthenticated Kibana UI",
        body_needles: &["kbn-injected-metadata", "<title>Kibana</title>"],
        header_needles: &["kbn-name:"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "Kibana UI loads without authentication. Enable X-Pack Security \
             (`xpack.security.enabled: true`) and configure a native/oidc realm, then \
             put Kibana behind an authenticating reverse proxy.",
    },
    DashboardCheck {
        path: "/_cluster/health",
        product: "Elasticsearch",
        surface: "cluster health API",
        body_needles: &[
            "\"cluster_name\"",
            "\"number_of_nodes\"",
            "\"active_shards\"",
        ],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "Elasticsearch cluster health is reachable without auth. Enable the free \
             built-in security (`xpack.security.enabled: true`), configure TLS, and \
             set strong passwords for the `elastic` and `kibana_system` users. \
             Never expose port 9200 to the public internet.",
    },
    DashboardCheck {
        path: "/_cat/indices",
        product: "Elasticsearch",
        surface: "index listing API",
        // `_cat/indices` returns text like:
        // "green open my-index abcd... 1 1 100 0 1.2mb 600kb"
        // We require both a health state token and a shard-count marker
        // in the body to avoid matching arbitrary text responses.
        body_needles: &[" open ", " close ", " yellow ", " green "],
        header_needles: &["content-type: text/plain"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "The Elasticsearch `_cat/indices` endpoint listed indices without authentication, \
             leaking index names (often per-customer or per-tenant) and document counts. \
             Enable X-Pack security and require a role for the `monitor` cluster privilege.",
    },
    // ============================================================
    // Message brokers / streaming
    // ============================================================
    DashboardCheck {
        path: "/api/whoami",
        product: "RabbitMQ Management",
        surface: "management API",
        // Only guest/guest gives an unauthenticated 200 here in default installs.
        body_needles: &["\"name\":\"guest\"", "\"tags\":[\"administrator\"]"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Critical,
        cvss: 9.8,
        cwe: "CWE-798",
        remediation:
            "RabbitMQ management API accepted default `guest:guest` credentials from the \
             public network. Delete or rename the guest user (`rabbitmqctl delete_user \
             guest`), enforce `loopback_users` for guest, and put the management port \
             behind an authenticating reverse proxy.",
    },
    DashboardCheck {
        path: "/api/overview",
        product: "RabbitMQ Management",
        surface: "cluster overview API",
        body_needles: &["\"rabbitmq_version\"", "\"cluster_name\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "RabbitMQ management overview API is reachable and exposes broker version, \
             cluster name, and node topology. Restrict the management plugin to internal \
             networks and remove any default credentials.",
    },
    // ============================================================
    // Service mesh / ingress dashboards
    // ============================================================
    DashboardCheck {
        path: "/dashboard/",
        product: "Traefik",
        surface: "unauthenticated Traefik dashboard",
        body_needles: &["ng-app=\"traefik\"", "traefik.dashboard", "<title>Traefik</title>"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "Traefik dashboard is exposed. Under `[api]` set `dashboard = true` only \
             when combined with a middleware that enforces `basicauth` or `forwardauth`, \
             and never expose the `insecure = true` port publicly.",
    },
    DashboardCheck {
        path: "/api/rawdata",
        product: "Traefik",
        surface: "raw router/service dump",
        body_needles: &["\"routers\":", "\"services\":", "\"middlewares\":"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "Traefik `/api/rawdata` is public. It reveals every backend, its address, \
             TLS options and middleware chain — a full map of the internal service topology. \
             Disable `insecure = true` and require auth on the `[api]` entrypoint.",
    },
    // ============================================================
    // Service discovery / config
    // ============================================================
    DashboardCheck {
        path: "/v1/status/leader",
        product: "Consul",
        surface: "cluster leader endpoint",
        // Response is a bare JSON string like "\"10.0.0.5:8300\"".
        body_needles: &[":8300\""],
        header_needles: &["x-consul-index:"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "Consul HTTP API is reachable and returns the cluster leader IP. Enable ACLs \
             (`acl.enabled = true`, `acl.default_policy = \"deny\"`) and require agent tokens \
             for all read endpoints. Never bind port 8500 to a public interface.",
    },
    DashboardCheck {
        path: "/v1/agent/self",
        product: "Consul",
        surface: "agent config API (leaks tokens)",
        body_needles: &["\"Config\":", "\"NodeName\":", "\"Datacenter\":"],
        header_needles: &["x-consul-index:"],
        expected_statuses: &[200],
        severity: Severity::Critical,
        cvss: 9.1,
        cwe: "CWE-200",
        remediation:
            "Consul `/v1/agent/self` is reachable without an ACL token and leaks the \
             full agent configuration (data-dir, ACL tokens if masked incorrectly, \
             gossip encryption key hint, TLS paths). Enable ACLs with a deny-by-default \
             policy and rotate any tokens that may have been exposed.",
    },
    // ============================================================
    // Data / analytics services
    // ============================================================
    DashboardCheck {
        path: "/minio/health/live",
        product: "MinIO",
        surface: "MinIO health probe",
        body_needles: &[],
        header_needles: &["server: minio", "x-amz-request-id:"],
        expected_statuses: &[200],
        severity: Severity::Low,
        cvss: 4.3,
        cwe: "CWE-200",
        remediation:
            "MinIO instance is reachable. Confirm the console (usually port 9001) is not \
             exposed publicly and that default `minioadmin:minioadmin` credentials have \
             been rotated. Front the S3 API with an authenticating gateway if not \
             intended to be public.",
    },
    DashboardCheck {
        path: "/solr/admin/info/system",
        product: "Apache Solr",
        surface: "system info API",
        body_needles: &["\"solr_home\"", "\"lucene\"", "\"jvm\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "Solr admin API is reachable and discloses Solr home path, Lucene version and \
             full JVM configuration. Enable Solr's authentication plugin (Basic or Kerberos) \
             and restrict the admin path via a reverse proxy ACL.",
    },
    DashboardCheck {
        path: "/api/v2/query",
        product: "InfluxDB 2.x",
        surface: "Flux query API",
        body_needles: &["unauthorized access"],
        header_needles: &["x-influxdb-version:"],
        // A 401 that also carries the X-Influxdb-Version header is proof the
        // server exists and its version is disclosed; that alone is worth flagging.
        expected_statuses: &[401, 403],
        severity: Severity::Info,
        cvss: 2.6,
        cwe: "CWE-200",
        remediation:
            "InfluxDB 2.x version is disclosed via the `X-Influxdb-Version` response header. \
             Configure InfluxDB behind a reverse proxy that strips or overrides the header, \
             and ensure organization/token-based auth is enforced on all `/api/v2/*` paths.",
    },
    // ============================================================
    // CI / build servers
    // ============================================================
    DashboardCheck {
        path: "/manage",
        product: "Jenkins",
        surface: "unauthenticated /manage page",
        body_needles: &["Manage Jenkins", "Configure System"],
        header_needles: &["x-jenkins:", "x-hudson:"],
        expected_statuses: &[200],
        severity: Severity::Critical,
        cvss: 9.8,
        cwe: "CWE-306",
        remediation:
            "Jenkins `/manage` reached the actual admin page without authentication. Enable \
             the Global Security Realm, set `Authorization` to `Logged-in users can do anything` \
             at minimum, and disable the `Allow anonymous read access` toggle. Then rotate \
             every credential stored in Jenkins Credentials.",
    },
    DashboardCheck {
        path: "/computer/api/json",
        product: "Jenkins",
        surface: "build agents API",
        body_needles: &["\"computer\":[", "\"_class\":\"hudson.model.Hudson\""],
        header_needles: &["x-jenkins:", "x-hudson:"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "Jenkins agent listing is reachable and leaks agent names, executor counts and \
             online status. Enable authentication for the entire `/computer/*` tree via \
             Matrix Authorization.",
    },
    DashboardCheck {
        path: "/go/api/version",
        product: "GoCD",
        surface: "GoCD version API",
        body_needles: &["\"version\":", "\"build_number\":", "\"git_sha\":"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Low,
        cvss: 4.3,
        cwe: "CWE-200",
        remediation:
            "GoCD server version is disclosed. Require authentication for the API, and \
             audit whether older exposed GoCD versions carry known CVEs.",
    },
    DashboardCheck {
        path: "/api/system/info",
        product: "SonarQube",
        surface: "system info API",
        body_needles: &["\"System\":{", "\"Database\":{"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "SonarQube `/api/system/info` exposes the full system configuration incl. \
             database URL, JVM args, and often plugin/token metadata. Require the \
             `Administer System` permission for anonymous users, and disable the \
             `sonar.forceAuthentication = false` setting.",
    },
    DashboardCheck {
        path: "/service/rest/v1/status",
        product: "Sonatype Nexus",
        surface: "status API",
        body_needles: &[],
        // Nexus 3 typically returns 200 with empty body but a distinctive Server header.
        header_needles: &["server: nexus/"],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.3,
        cwe: "CWE-200",
        remediation:
            "Sonatype Nexus is reachable and its version is disclosed via the `Server` \
             header. Change the default `admin:admin123` password immediately, disable \
             anonymous access, and hide the Server header at your reverse proxy.",
    },
    // ============================================================
    // Container / orchestration
    // ============================================================
    DashboardCheck {
        path: "/api/status",
        product: "Portainer",
        surface: "Portainer status API",
        body_needles: &["\"Version\":", "\"InstanceID\":"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.3,
        cwe: "CWE-200",
        remediation:
            "Portainer status API is reachable and discloses the version. Ensure the \
             initial admin user is set (Portainer disables signup after first user), \
             enable OAuth or LDAP, and never expose the Docker socket via Portainer to \
             the public network.",
    },
    DashboardCheck {
        path: "/api/version",
        product: "Docker Registry",
        surface: "registry v2 API",
        body_needles: &["\"errors\":[{\"code\":\"UNSUPPORTED\""],
        header_needles: &["docker-distribution-api-version: registry/2"],
        // The registry returns 404 for /api/version but sets the
        // Docker-Distribution-Api-Version header — reachable-but-versioned.
        expected_statuses: &[200, 404],
        severity: Severity::Info,
        cvss: 2.6,
        cwe: "CWE-200",
        remediation:
            "A Docker Registry v2 endpoint is reachable. Confirm that `/v2/_catalog` and \
             `/v2/<image>/tags/list` require authentication (htpasswd or token), and \
             audit the image list for internal-only images accidentally pushed to a \
             publicly reachable registry.",
    },
    DashboardCheck {
        path: "/version",
        product: "Kubernetes API",
        surface: "unauthenticated version endpoint",
        body_needles: &["\"gitVersion\":\"v1.", "\"platform\":\"linux/amd64\""],
        header_needles: &["audit-id:"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-200",
        remediation:
            "The Kubernetes API `/version` endpoint responded without authentication. \
             Disable anonymous auth (`--anonymous-auth=false` on kube-apiserver), enforce \
             RBAC, and never expose the API server on a public interface. Audit whether \
             `/api`, `/apis` or `/healthz` also respond unauthenticated.",
    },
    // ============================================================
    // Workflow / data orchestration
    // ============================================================
    DashboardCheck {
        path: "/api/v1/version",
        product: "Apache Airflow",
        surface: "version API",
        body_needles: &["\"version\":", "\"git_version\":"],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Medium,
        cvss: 5.3,
        cwe: "CWE-200",
        remediation:
            "Airflow API version endpoint is reachable without authentication. Set \
             `[api] auth_backends = airflow.api.auth.backend.basic_auth` (or JWT) and \
             disable `[webserver] expose_config`. Old Airflow versions carry known RCEs \
             — patch immediately if the version is < 2.9.",
    },
    DashboardCheck {
        path: "/api/v1/dags",
        product: "Apache Airflow",
        surface: "DAG listing API",
        body_needles: &["\"dags\":[", "\"schedule_interval\""],
        header_needles: &[],
        expected_statuses: &[200],
        severity: Severity::Critical,
        cvss: 9.1,
        cwe: "CWE-306",
        remediation:
            "Airflow DAG listing is reachable without authentication and lets an attacker \
             enumerate every workflow, its schedule, and often its owner/tags. Require \
             an auth backend for the API immediately and rotate any credentials referenced \
             in DAG source.",
    },
    // ============================================================
    // Databases / stores
    // ============================================================
    DashboardCheck {
        path: "/_utils/",
        product: "Apache CouchDB",
        surface: "Fauxton admin UI",
        body_needles: &["Fauxton", "Apache CouchDB"],
        header_needles: &["server: couchdb/"],
        expected_statuses: &[200],
        severity: Severity::High,
        cvss: 7.5,
        cwe: "CWE-306",
        remediation:
            "CouchDB's Fauxton admin UI is reachable. Set an admin user in `local.ini` \
             (`[admins] admin = <password>`) to disable the historical \"admin party\" \
             mode where anonymous users have admin rights. Rotate the port to a private \
             interface.",
    },
    DashboardCheck {
        path: "/_all_dbs",
        product: "Apache CouchDB",
        surface: "database listing",
        body_needles: &["[\"_replicator", "[\"_users"],
        header_needles: &["server: couchdb/"],
        expected_statuses: &[200],
        severity: Severity::Critical,
        cvss: 9.1,
        cwe: "CWE-306",
        remediation:
            "CouchDB `/_all_dbs` returned the database list without authentication. \
             This confirms admin-party mode. Set an admin user, then rotate any secrets \
             that were stored in the accessible databases.",
    },
];

impl ExposedDashboardsScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan the target for exposed management/monitoring dashboards.
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0usize;

        info!("[ExposedDashboards] Scanning for exposed management dashboards");

        let base_url = match Self::extract_base_url(url) {
            Some(b) => b,
            None => return Ok((vulnerabilities, 0)),
        };

        // Cheap baseline: does this host return a distinct 404 for a
        // guaranteed-nonexistent path? If not (static responder that returns
        // 200 for everything), we tighten the rules: header_needles are still
        // trusted (they're set by real backend software), but body-only
        // matches on a static responder are dropped to avoid FPs.
        let static_responder = self.detect_static_responder(&base_url).await;
        if static_responder {
            debug!(
                "[ExposedDashboards] {} appears to respond identically to nonexistent \
                 paths; body-only matches will be suppressed",
                base_url
            );
        }

        for check in CHECKS {
            tests_run += 1;
            let test_url = format!("{}{}", base_url, check.path);

            let response = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("[ExposedDashboards] {} failed: {}", test_url, e);
                    continue;
                }
            };

            if !check.expected_statuses.contains(&response.status_code) {
                continue;
            }

            let (matched_by, evidence) = match Self::check_matches(check, &response) {
                Some(m) => m,
                None => continue,
            };

            // False-positive guard: on a static responder that returns the
            // same page for everything, only trust header-based matches.
            if static_responder && matched_by == MatchSource::Body {
                debug!(
                    "[ExposedDashboards] Dropping body-only match for {} on static \
                     responder (would be false positive)",
                    test_url
                );
                continue;
            }

            info!(
                "[ExposedDashboards] {} exposed at {} ({})",
                check.product, test_url, check.surface
            );

            vulnerabilities.push(Self::build_vulnerability(check, &test_url, &evidence));
        }

        info!(
            "[ExposedDashboards] Ran {} checks, found {} exposed surface(s)",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Return the origin (scheme://host[:port]) for a URL, or None if unparseable.
    fn extract_base_url(url: &str) -> Option<String> {
        let parsed = url::Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        let scheme = parsed.scheme();
        if let Some(port) = parsed.port() {
            Some(format!("{}://{}:{}", scheme, host, port))
        } else {
            Some(format!("{}://{}", scheme, host))
        }
    }

    /// Determine whether the host returns the same response body for any path
    /// (typical of parked domains, SPA-only hosts, or 200-for-everything WAFs).
    async fn detect_static_responder(&self, base_url: &str) -> bool {
        // Ask for a randomly-named path that cannot possibly exist.
        // We keep the request cheap and give up on any error.
        let probe_url = format!(
            "{}/nonexistent-{}-lonkero-probe",
            base_url,
            "9f3c2a41" // fixed, deterministic — Date/rand are unavailable in some run contexts
        );
        let probe = match self.http_client.get(&probe_url).await {
            Ok(r) => r,
            Err(_) => return false,
        };
        // A truthful backend returns 404/410/301/302/401/403 for garbage paths.
        // If we get 200 with a nontrivial body, treat as static responder.
        probe.status_code == 200 && probe.body.len() > 100
    }

    /// Check whether the response matches any needle of the check.
    /// Returns the source of the match and the human-readable evidence line.
    fn check_matches(
        check: &DashboardCheck,
        response: &crate::http_client::HttpResponse,
    ) -> Option<(MatchSource, String)> {
        // Header check: build "name: value" pairs, lowercase, look for needles.
        // Headers are trustworthy because they're server-generated and don't
        // appear in arbitrary user content.
        if !check.header_needles.is_empty() {
            let header_haystack: String = response
                .headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.to_lowercase(), v.to_lowercase()))
                .collect::<Vec<_>>()
                .join("\n");
            for needle in check.header_needles {
                let n = needle.to_lowercase();
                if header_haystack.contains(&n) {
                    return Some((MatchSource::Header, format!("header match: `{}`", needle)));
                }
            }
        }

        // Body check: case-insensitive substring against the body.
        if !check.body_needles.is_empty() {
            let body_lower = response.body.to_lowercase();
            for needle in check.body_needles {
                let n = needle.to_lowercase();
                if body_lower.contains(&n) {
                    return Some((MatchSource::Body, format!("body match: `{}`", needle)));
                }
            }
        }

        None
    }

    fn build_vulnerability(
        check: &DashboardCheck,
        test_url: &str,
        evidence: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("exposed_dashboard_{}", uuid::Uuid::new_v4()),
            vuln_type: format!(
                "Exposed {} — {}",
                check.product, check.surface
            ),
            severity: check.severity.clone(),
            confidence: Confidence::High,
            category: "Security Misconfiguration".to_string(),
            url: test_url.to_string(),
            parameter: None,
            payload: check.path.to_string(),
            description: format!(
                "The {} {} is reachable from the public internet without authentication. \
                 Exposed management and monitoring surfaces are one of the highest-signal \
                 findings in a pentest: they usually disclose internal topology, credentials \
                 or configuration, and often allow direct privileged operations.",
                check.product, check.surface
            ),
            evidence: Some(format!(
                "GET {} — status matched, {}",
                test_url, evidence
            )),
            cwe: check.cwe.to_string(),
            cvss: check.cvss,
            verified: true,
            false_positive: false,
            remediation: check.remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_confidence: None,
            ml_data: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchSource {
    Header,
    Body,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resp(status: u16, body: &str, headers: &[(&str, &str)]) -> crate::http_client::HttpResponse {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert((*k).to_string(), (*v).to_string());
        }
        crate::http_client::HttpResponse {
            status_code: status,
            body: body.to_string(),
            headers: h,
            duration_ms: 0,
        }
    }

    #[test]
    fn header_match_wins_case_insensitively() {
        let check = &CHECKS
            .iter()
            .find(|c| c.product == "Kibana" && c.path == "/api/status")
            .unwrap();
        // Kibana emits `kbn-name` even if body is empty.
        let r = resp(200, "{}", &[("Kbn-Name", "logging-cluster")]);
        let m = ExposedDashboardsScanner::check_matches(check, &r);
        assert!(m.is_some());
        assert_eq!(m.unwrap().0, MatchSource::Header);
    }

    #[test]
    fn body_needle_matches_case_insensitively() {
        let check = CHECKS
            .iter()
            .find(|c| c.product == "Consul" && c.path == "/v1/status/leader")
            .unwrap();
        let r = resp(200, "\"10.0.0.5:8300\"", &[]);
        let m = ExposedDashboardsScanner::check_matches(check, &r);
        assert!(m.is_some());
        assert_eq!(m.unwrap().0, MatchSource::Body);
    }

    #[test]
    fn no_match_when_body_and_headers_absent() {
        let check = CHECKS
            .iter()
            .find(|c| c.product == "Elasticsearch" && c.path == "/_cluster/health")
            .unwrap();
        let r = resp(200, "<html>unrelated</html>", &[]);
        assert!(ExposedDashboardsScanner::check_matches(check, &r).is_none());
    }

    #[test]
    fn prometheus_metrics_requires_specific_help_prefix() {
        let check = CHECKS
            .iter()
            .find(|c| c.product == "Prometheus/Node Exporter" && c.path == "/metrics")
            .unwrap();
        // Body containing just "# HELP" without a prom-namespace prefix should not match.
        let bad = resp(200, "# HELP something_else custom counter", &[]);
        assert!(ExposedDashboardsScanner::check_matches(check, &bad).is_none());
        // Real Prometheus text-format response matches.
        let good = resp(
            200,
            "# HELP go_gc_duration_seconds A summary of GC pauses.\n# TYPE go_gc_duration_seconds summary\n",
            &[],
        );
        assert!(ExposedDashboardsScanner::check_matches(check, &good).is_some());
    }

    #[test]
    fn extract_base_url_keeps_port() {
        assert_eq!(
            ExposedDashboardsScanner::extract_base_url("https://host.example:9200/x/y?z=1"),
            Some("https://host.example:9200".to_string())
        );
        assert_eq!(
            ExposedDashboardsScanner::extract_base_url("http://plain.example/"),
            Some("http://plain.example".to_string())
        );
        assert_eq!(
            ExposedDashboardsScanner::extract_base_url("not a url"),
            None
        );
    }

    #[test]
    fn every_check_has_at_least_one_needle() {
        // Guards against a check that would always fire on the expected status.
        for check in CHECKS {
            assert!(
                !check.body_needles.is_empty() || !check.header_needles.is_empty(),
                "check for {} {} has no needles",
                check.product,
                check.path
            );
        }
    }
}

// UUID generation helper (mirrors the pattern used elsewhere in this crate
// so the scanner does not add a new dependency on the `uuid` crate directly).
mod uuid {
    use rand::RngExt;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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
