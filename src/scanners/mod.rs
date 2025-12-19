// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Security Scanner Engine
 * Main scan orchestration and coordination
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::config::ScannerConfig;
use crate::crawler::{WebCrawler, CrawlResults};
use crate::framework_detector::FrameworkDetector;
use crate::http_client::HttpClient;
use crate::queue::RedisQueue;
use crate::rate_limiter::{AdaptiveRateLimiter, RateLimiterConfig};
use crate::subdomain_enum::SubdomainEnumerator;
use crate::types::{ScanJob, ScanMode, ScanResults, Severity, Vulnerability};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

pub mod xss_detection;
pub mod xss_enhanced;
pub mod sqli_enhanced;
pub mod baseline_detector;
pub mod command_injection;
pub mod path_traversal;
pub mod ssrf;
pub mod ssrf_blind;
pub mod jwt;
pub mod nosql;
pub mod security_headers;
pub mod cors;
pub mod firebase;
pub mod csrf;
pub mod xxe;
pub mod graphql;
pub mod oauth;
pub mod saml;
pub mod websocket;
pub mod grpc;
pub mod auth_bypass;
pub mod session_management;
pub mod mfa;
pub mod idor;
pub mod bola;
pub mod auth_manager;
pub mod advanced_auth;
pub mod ldap_injection;
pub mod file_upload;
pub mod open_redirect;
pub mod clickjacking;
pub mod crlf_injection;
pub mod email_header_injection;
pub mod template_injection;
pub mod deserialization;
pub mod prototype_pollution;
pub mod api_security;
pub mod http_smuggling;
pub mod xml_injection;
pub mod xpath_injection;
pub mod code_injection;
pub mod ssi_injection;
pub mod race_condition;
pub mod mass_assignment;
pub mod information_disclosure;
pub mod host_header_injection;
pub mod cache_poisoning;
pub mod business_logic;
pub mod jwt_vulnerabilities;
pub mod graphql_security;
pub mod nosql_injection;
pub mod file_upload_vulnerabilities;
pub mod cors_misconfiguration;
pub mod cloud_storage;
pub mod framework_vulnerabilities;
pub mod js_miner;
pub mod sensitive_data;
pub mod api_fuzzer;
pub mod api_gateway_scanner;
pub mod cloud_security_scanner;
pub mod container_scanner;
pub mod webauthn_scanner;
pub mod http3_scanner;
pub mod ssti_advanced_scanner;
pub mod cve_2025_55182;
pub mod cve_2025_55183;
pub mod cve_2025_55184;
pub mod azure_apim;
pub mod redos;
pub mod http_parameter_pollution;
pub mod waf_bypass;
pub mod merlin;
pub mod tomcat_misconfig;
pub mod varnish_misconfig;
pub mod js_sensitive_info;
pub mod client_route_auth_bypass;
pub mod rate_limiting;
pub mod html_injection;
pub mod wordpress_security;
pub mod drupal_security;
pub mod laravel_security;
pub mod express_security;
pub mod nextjs_security;
pub mod sveltekit_security;
pub mod react_security;
pub mod django_security;
pub mod liferay_security;
pub mod parameter_filter;

// External security scanners
pub mod external;

// Re-export scanner types for easy access
pub use xss_enhanced::EnhancedXssScanner as XssScanner;
pub use sqli_enhanced::EnhancedSqliScanner as SqliScanner;
pub use command_injection::CommandInjectionScanner;
pub use path_traversal::PathTraversalScanner;
pub use ssrf::SsrfScanner;
pub use ssrf_blind::SsrfBlindScanner;
pub use jwt::JwtScanner;
pub use nosql::NoSqlScanner;
pub use security_headers::SecurityHeadersScanner;
pub use cors::CorsScanner;
pub use firebase::FirebaseScanner;
pub use csrf::CsrfScanner;
pub use xxe::XxeScanner;
pub use graphql::GraphQlScanner;
pub use oauth::OAuthScanner;
pub use saml::SamlScanner;
pub use websocket::WebSocketScanner;
pub use grpc::GrpcScanner;
pub use auth_bypass::AuthBypassScanner;
pub use session_management::SessionManagementScanner;
pub use mfa::MfaScanner;
pub use idor::IdorScanner;
pub use bola::BolaScanner;
pub use auth_manager::AuthManagerScanner;
pub use advanced_auth::AdvancedAuthScanner;
pub use ldap_injection::LdapInjectionScanner;
pub use file_upload::FileUploadScanner;
pub use open_redirect::OpenRedirectScanner;
pub use clickjacking::ClickjackingScanner;
pub use crlf_injection::CrlfInjectionScanner;
pub use email_header_injection::EmailHeaderInjectionScanner;
pub use template_injection::TemplateInjectionScanner;
pub use deserialization::DeserializationScanner;
pub use prototype_pollution::PrototypePollutionScanner;
pub use api_security::APISecurityScanner;
pub use http_smuggling::HTTPSmugglingScanner;
pub use xml_injection::XMLInjectionScanner;
pub use xpath_injection::XPathInjectionScanner;
pub use code_injection::CodeInjectionScanner;
pub use ssi_injection::SSIInjectionScanner;
pub use race_condition::RaceConditionScanner;
pub use mass_assignment::MassAssignmentScanner;
pub use information_disclosure::InformationDisclosureScanner;
pub use host_header_injection::HostHeaderInjectionScanner;
pub use cache_poisoning::CachePoisoningScanner;
pub use business_logic::BusinessLogicScanner;
pub use jwt_vulnerabilities::JwtVulnerabilitiesScanner;
pub use graphql_security::GraphqlSecurityScanner;
pub use nosql_injection::NosqlInjectionScanner;
pub use file_upload_vulnerabilities::FileUploadVulnerabilitiesScanner;
pub use cors_misconfiguration::CorsMisconfigurationScanner;
pub use cloud_storage::CloudStorageScanner;
pub use framework_vulnerabilities::FrameworkVulnerabilitiesScanner;
pub use js_miner::{JsMinerScanner, JsMinerResults};
pub use sensitive_data::SensitiveDataScanner;
pub use api_fuzzer::ApiFuzzerScanner;
pub use api_gateway_scanner::ApiGatewayScanner;
pub use cloud_security_scanner::CloudSecurityScanner;
pub use container_scanner::ContainerScanner;
pub use webauthn_scanner::WebAuthnScanner;
pub use http3_scanner::Http3Scanner;
pub use ssti_advanced_scanner::SstiAdvancedScanner;
pub use cve_2025_55182::Cve202555182Scanner;
pub use cve_2025_55183::Cve202555183Scanner;
pub use cve_2025_55184::Cve202555184Scanner;
pub use azure_apim::AzureApimScanner;
pub use redos::RedosScanner;
pub use http_parameter_pollution::HttpParameterPollutionScanner;
pub use waf_bypass::WafBypassScanner;
pub use merlin::MerlinScanner;
pub use tomcat_misconfig::TomcatMisconfigScanner;
pub use varnish_misconfig::VarnishMisconfigScanner;
pub use js_sensitive_info::JsSensitiveInfoScanner;
pub use client_route_auth_bypass::ClientRouteAuthBypassScanner;
pub use rate_limiting::RateLimitingScanner;
pub use wordpress_security::WordPressSecurityScanner;
pub use drupal_security::DrupalSecurityScanner;
pub use laravel_security::LaravelSecurityScanner;
pub use express_security::ExpressSecurityScanner;
pub use nextjs_security::NextJsSecurityScanner;
pub use sveltekit_security::SvelteKitSecurityScanner;
pub use react_security::ReactSecurityScanner;
pub use django_security::DjangoSecurityScanner;
pub use liferay_security::LiferaySecurityScanner;

pub struct ScanEngine {
    pub config: ScannerConfig,
    pub http_client: Arc<HttpClient>,
    pub request_batcher: Option<Arc<crate::request_batcher::RequestBatcher>>,
    pub adaptive_concurrency: Option<Arc<crate::adaptive_concurrency::AdaptiveConcurrencyTracker>>,
    pub dns_cache: Option<Arc<crate::dns_cache::DnsCache>>,
    pub xss_scanner: XssScanner,
    pub sqli_scanner: SqliScanner,
    pub cmdi_scanner: CommandInjectionScanner,
    pub path_scanner: PathTraversalScanner,
    pub ssrf_scanner: SsrfScanner,
    pub ssrf_blind_scanner: SsrfBlindScanner,
    pub jwt_scanner: JwtScanner,
    pub nosql_scanner: NoSqlScanner,
    pub security_headers_scanner: SecurityHeadersScanner,
    pub cors_scanner: CorsScanner,
    pub firebase_scanner: FirebaseScanner,
    pub csrf_scanner: CsrfScanner,
    pub xxe_scanner: XxeScanner,
    pub graphql_scanner: GraphQlScanner,
    pub oauth_scanner: OAuthScanner,
    pub saml_scanner: SamlScanner,
    pub websocket_scanner: WebSocketScanner,
    pub grpc_scanner: GrpcScanner,
    pub auth_bypass_scanner: AuthBypassScanner,
    pub session_management_scanner: SessionManagementScanner,
    pub mfa_scanner: MfaScanner,
    pub idor_scanner: IdorScanner,
    pub bola_scanner: BolaScanner,
    pub auth_manager_scanner: AuthManagerScanner,
    pub advanced_auth_scanner: AdvancedAuthScanner,
    pub ldap_injection_scanner: LdapInjectionScanner,
    pub file_upload_scanner: FileUploadScanner,
    pub open_redirect_scanner: Arc<OpenRedirectScanner>,
    pub clickjacking_scanner: ClickjackingScanner,
    pub crlf_injection_scanner: CrlfInjectionScanner,
    pub email_header_injection_scanner: EmailHeaderInjectionScanner,
    pub template_injection_scanner: TemplateInjectionScanner,
    pub deserialization_scanner: DeserializationScanner,
    pub prototype_pollution_scanner: PrototypePollutionScanner,
    pub api_security_scanner: APISecurityScanner,
    pub http_smuggling_scanner: HTTPSmugglingScanner,
    pub xml_injection_scanner: XMLInjectionScanner,
    pub xpath_injection_scanner: XPathInjectionScanner,
    pub code_injection_scanner: CodeInjectionScanner,
    pub ssi_injection_scanner: SSIInjectionScanner,
    pub race_condition_scanner: RaceConditionScanner,
    pub mass_assignment_scanner: MassAssignmentScanner,
    pub information_disclosure_scanner: InformationDisclosureScanner,
    pub host_header_injection_scanner: HostHeaderInjectionScanner,
    pub cache_poisoning_scanner: CachePoisoningScanner,
    pub business_logic_scanner: BusinessLogicScanner,
    pub jwt_vulnerabilities_scanner: JwtVulnerabilitiesScanner,
    pub graphql_security_scanner: GraphqlSecurityScanner,
    pub nosql_injection_scanner: NosqlInjectionScanner,
    pub file_upload_vulnerabilities_scanner: FileUploadVulnerabilitiesScanner,
    pub cors_misconfiguration_scanner: CorsMisconfigurationScanner,
    pub cloud_storage_scanner: CloudStorageScanner,
    pub framework_vulnerabilities_scanner: FrameworkVulnerabilitiesScanner,
    pub js_miner_scanner: JsMinerScanner,
    pub sensitive_data_scanner: SensitiveDataScanner,
    pub api_fuzzer_scanner: ApiFuzzerScanner,
    pub api_gateway_scanner: ApiGatewayScanner,
    pub cloud_security_scanner: CloudSecurityScanner,
    pub container_scanner: ContainerScanner,
    pub webauthn_scanner: WebAuthnScanner,
    pub http3_scanner: Http3Scanner,
    pub ssti_advanced_scanner: SstiAdvancedScanner,
    pub cve_2025_55182_scanner: Cve202555182Scanner,
    pub cve_2025_55183_scanner: Cve202555183Scanner,
    pub cve_2025_55184_scanner: Cve202555184Scanner,
    pub azure_apim_scanner: AzureApimScanner,
    pub redos_scanner: RedosScanner,
    pub hpp_scanner: HttpParameterPollutionScanner,
    pub waf_bypass_scanner: WafBypassScanner,
    pub merlin_scanner: MerlinScanner,
    pub tomcat_misconfig_scanner: TomcatMisconfigScanner,
    pub varnish_misconfig_scanner: VarnishMisconfigScanner,
    pub js_sensitive_info_scanner: JsSensitiveInfoScanner,
    pub client_route_auth_bypass_scanner: ClientRouteAuthBypassScanner,
    pub rate_limiting_scanner: RateLimitingScanner,
    pub wordpress_security_scanner: WordPressSecurityScanner,
    pub drupal_security_scanner: DrupalSecurityScanner,
    pub laravel_security_scanner: LaravelSecurityScanner,
    pub express_security_scanner: ExpressSecurityScanner,
    pub nextjs_security_scanner: NextJsSecurityScanner,
    pub sveltekit_security_scanner: SvelteKitSecurityScanner,
    pub react_security_scanner: ReactSecurityScanner,
    pub django_security_scanner: DjangoSecurityScanner,
    pub liferay_security_scanner: LiferaySecurityScanner,
    pub subdomain_enumerator: SubdomainEnumerator,
}

impl ScanEngine {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        // Create HTTP client with optimizations
        let mut http_client = HttpClient::with_config(
            config.request_timeout_secs,
            config.max_retries,
            config.http2_enabled,
            config.http2_adaptive_window,
            config.http2_max_concurrent_streams,
            config.pool_max_idle_per_host,
        )?;

        // Log HTTP/2 status
        if config.http2_enabled {
            info!("[SUCCESS] HTTP/2 enabled: streams={}, pool={}",
                  config.http2_max_concurrent_streams, config.pool_max_idle_per_host);
        } else {
            info!("[WARNING]  HTTP/2 disabled");
        }

        // Add response caching if enabled
        if config.cache_enabled {
            http_client = http_client.with_cache(
                config.cache_max_capacity as u64,
                config.cache_ttl_secs,
            );
            info!("[SUCCESS] Response cache enabled: capacity={}, ttl={}s",
                  config.cache_max_capacity, config.cache_ttl_secs);
        } else {
            info!("[WARNING]  Response cache disabled");
        }

        // Add rate limiter if enabled
        if config.rate_limit_enabled {
            let rate_limiter_config = RateLimiterConfig {
                default_rps: config.rate_limit_rps,
                min_rps: 10,
                max_rps: config.rate_limit_rps * 10,
                backoff_multiplier: 0.5,
                recovery_multiplier: 1.1,
                adaptive: config.rate_limit_adaptive,
            };

            let rate_limiter = Arc::new(AdaptiveRateLimiter::new(rate_limiter_config));
            http_client = http_client.with_rate_limiter(rate_limiter);

            info!("[SUCCESS] Rate limiting enabled: {}rps, adaptive={}",
                  config.rate_limit_rps, config.rate_limit_adaptive);
        } else {
            info!("[WARNING]  Rate limiting disabled");
        }

        let http_client = Arc::new(http_client);

        // Phase 3: Advanced Tuning
        let request_batcher = if config.request_batching_enabled {
            let batcher = Arc::new(crate::request_batcher::RequestBatcher::new(
                Arc::clone(&http_client),
                config.batch_size,
            ));
            info!("[SUCCESS] Request batching enabled: batch_size={}", config.batch_size);
            Some(batcher)
        } else {
            info!("[WARNING]  Request batching disabled");
            None
        };

        let adaptive_concurrency = if config.adaptive_concurrency_enabled {
            let tracker = Arc::new(crate::adaptive_concurrency::AdaptiveConcurrencyTracker::new(
                config.initial_concurrency,
                config.max_concurrency_per_target,
            ));
            info!("[SUCCESS] Adaptive concurrency enabled: initial={}, max={}",
                  config.initial_concurrency, config.max_concurrency_per_target);
            Some(tracker)
        } else {
            info!("[WARNING]  Adaptive concurrency disabled");
            None
        };

        let dns_cache = if config.dns_cache_enabled {
            let cache = Arc::new(crate::dns_cache::DnsCache::new());
            info!("[SUCCESS] DNS caching enabled");
            Some(cache)
        } else {
            info!("[WARNING]  DNS caching disabled");
            None
        };

        Ok(Self {
            request_batcher,
            adaptive_concurrency,
            dns_cache,
            xss_scanner: XssScanner::new(Arc::clone(&http_client)),
            sqli_scanner: SqliScanner::new(Arc::clone(&http_client)),
            cmdi_scanner: CommandInjectionScanner::new(Arc::clone(&http_client)),
            path_scanner: PathTraversalScanner::new(Arc::clone(&http_client)),
            ssrf_scanner: SsrfScanner::new(Arc::clone(&http_client)),
            ssrf_blind_scanner: SsrfBlindScanner::new(Arc::clone(&http_client)),
            jwt_scanner: JwtScanner::new(Arc::clone(&http_client)),
            nosql_scanner: NoSqlScanner::new(Arc::clone(&http_client)),
            security_headers_scanner: SecurityHeadersScanner::new(Arc::clone(&http_client)),
            cors_scanner: CorsScanner::new(Arc::clone(&http_client)),
            firebase_scanner: FirebaseScanner::new(Arc::clone(&http_client)),
            csrf_scanner: CsrfScanner::new(Arc::clone(&http_client)),
            xxe_scanner: XxeScanner::new(Arc::clone(&http_client)),
            graphql_scanner: GraphQlScanner::new(Arc::clone(&http_client)),
            oauth_scanner: OAuthScanner::new(Arc::clone(&http_client)),
            saml_scanner: SamlScanner::new(Arc::clone(&http_client)),
            websocket_scanner: WebSocketScanner::new(Arc::clone(&http_client)),
            grpc_scanner: GrpcScanner::new(Arc::clone(&http_client)),
            auth_bypass_scanner: AuthBypassScanner::new(Arc::clone(&http_client)),
            session_management_scanner: SessionManagementScanner::new(Arc::clone(&http_client)),
            mfa_scanner: MfaScanner::new(Arc::clone(&http_client)),
            idor_scanner: IdorScanner::new(Arc::clone(&http_client)),
            bola_scanner: BolaScanner::new(Arc::clone(&http_client)),
            auth_manager_scanner: AuthManagerScanner::new(Arc::clone(&http_client)),
            advanced_auth_scanner: AdvancedAuthScanner::new(Arc::clone(&http_client)),
            ldap_injection_scanner: LdapInjectionScanner::new(Arc::clone(&http_client)),
            file_upload_scanner: FileUploadScanner::new(Arc::clone(&http_client)),
            open_redirect_scanner: Arc::new(OpenRedirectScanner::new(Arc::clone(&http_client))),
            clickjacking_scanner: ClickjackingScanner::new(Arc::clone(&http_client)),
            crlf_injection_scanner: CrlfInjectionScanner::new(Arc::clone(&http_client)),
            email_header_injection_scanner: EmailHeaderInjectionScanner::new(Arc::clone(&http_client)),
            template_injection_scanner: TemplateInjectionScanner::new(Arc::clone(&http_client)),
            deserialization_scanner: DeserializationScanner::new(Arc::clone(&http_client)),
            prototype_pollution_scanner: PrototypePollutionScanner::new(Arc::clone(&http_client)),
            api_security_scanner: APISecurityScanner::new(Arc::clone(&http_client)),
            http_smuggling_scanner: HTTPSmugglingScanner::new(Arc::clone(&http_client)),
            xml_injection_scanner: XMLInjectionScanner::new(Arc::clone(&http_client)),
            xpath_injection_scanner: XPathInjectionScanner::new(Arc::clone(&http_client)),
            code_injection_scanner: CodeInjectionScanner::new(Arc::clone(&http_client)),
            ssi_injection_scanner: SSIInjectionScanner::new(Arc::clone(&http_client)),
            race_condition_scanner: RaceConditionScanner::new(Arc::clone(&http_client)),
            mass_assignment_scanner: MassAssignmentScanner::new(Arc::clone(&http_client)),
            information_disclosure_scanner: InformationDisclosureScanner::new(Arc::clone(&http_client)),
            host_header_injection_scanner: HostHeaderInjectionScanner::new(Arc::clone(&http_client)),
            cache_poisoning_scanner: CachePoisoningScanner::new(Arc::clone(&http_client)),
            business_logic_scanner: BusinessLogicScanner::new(Arc::clone(&http_client)),
            jwt_vulnerabilities_scanner: JwtVulnerabilitiesScanner::new(Arc::clone(&http_client)),
            graphql_security_scanner: GraphqlSecurityScanner::new(Arc::clone(&http_client)),
            nosql_injection_scanner: NosqlInjectionScanner::new(Arc::clone(&http_client)),
            file_upload_vulnerabilities_scanner: FileUploadVulnerabilitiesScanner::new(Arc::clone(&http_client)),
            cors_misconfiguration_scanner: CorsMisconfigurationScanner::new(Arc::clone(&http_client)),
            cloud_storage_scanner: CloudStorageScanner::new(Arc::clone(&http_client)),
            framework_vulnerabilities_scanner: FrameworkVulnerabilitiesScanner::new(Arc::clone(&http_client)),
            js_miner_scanner: JsMinerScanner::new(Arc::clone(&http_client)),
            sensitive_data_scanner: SensitiveDataScanner::new(Arc::clone(&http_client)),
            api_fuzzer_scanner: ApiFuzzerScanner::new(Arc::clone(&http_client)),
            api_gateway_scanner: ApiGatewayScanner::new(Arc::clone(&http_client)),
            cloud_security_scanner: CloudSecurityScanner::new(Arc::clone(&http_client)),
            container_scanner: ContainerScanner::new(Arc::clone(&http_client)),
            webauthn_scanner: WebAuthnScanner::new(Arc::clone(&http_client)),
            http3_scanner: Http3Scanner::new(Arc::clone(&http_client)),
            ssti_advanced_scanner: SstiAdvancedScanner::new(Arc::clone(&http_client)),
            cve_2025_55182_scanner: Cve202555182Scanner::new(Arc::clone(&http_client)),
            cve_2025_55183_scanner: Cve202555183Scanner::new(Arc::clone(&http_client)),
            cve_2025_55184_scanner: Cve202555184Scanner::new(Arc::clone(&http_client)),
            azure_apim_scanner: AzureApimScanner::new(Arc::clone(&http_client)),
            redos_scanner: RedosScanner::new(Arc::clone(&http_client)),
            hpp_scanner: HttpParameterPollutionScanner::new(Arc::clone(&http_client)),
            waf_bypass_scanner: WafBypassScanner::new(Arc::clone(&http_client)),
            merlin_scanner: MerlinScanner::new(Arc::clone(&http_client)),
            tomcat_misconfig_scanner: TomcatMisconfigScanner::new(Arc::clone(&http_client)),
            varnish_misconfig_scanner: VarnishMisconfigScanner::new(Arc::clone(&http_client)),
            js_sensitive_info_scanner: JsSensitiveInfoScanner::new(Arc::clone(&http_client)),
            client_route_auth_bypass_scanner: ClientRouteAuthBypassScanner::new(Arc::clone(&http_client)),
            rate_limiting_scanner: RateLimitingScanner::new(Arc::clone(&http_client)),
            wordpress_security_scanner: WordPressSecurityScanner::new(Arc::clone(&http_client)),
            drupal_security_scanner: DrupalSecurityScanner::new(Arc::clone(&http_client)),
            laravel_security_scanner: LaravelSecurityScanner::new(Arc::clone(&http_client)),
            express_security_scanner: ExpressSecurityScanner::new(Arc::clone(&http_client)),
            nextjs_security_scanner: NextJsSecurityScanner::new(Arc::clone(&http_client)),
            sveltekit_security_scanner: SvelteKitSecurityScanner::new(Arc::clone(&http_client)),
            react_security_scanner: ReactSecurityScanner::new(Arc::clone(&http_client)),
            django_security_scanner: DjangoSecurityScanner::new(Arc::clone(&http_client)),
            liferay_security_scanner: LiferaySecurityScanner::new(Arc::clone(&http_client)),
            subdomain_enumerator: SubdomainEnumerator::new(Arc::clone(&http_client)),
            http_client,
            config,
        })
    }

    /// Execute a complete scan job
    ///
    /// IMPORTANT: This function requires prior authorization via `crate::signing::authorize_scan()`.
    /// Unauthorized scans will be rejected to prevent bypass of ban enforcement.
    pub async fn execute_scan(
        &self,
        job: Arc<ScanJob>,
        queue: Arc<RedisQueue>,
    ) -> Result<ScanResults> {
        let start_time = Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();

        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        // This check ensures banned users cannot scan. The authorization
        // must be obtained BEFORE this function is called.
        if !crate::signing::is_scan_authorized() {
            return Err(anyhow::anyhow!(
                "SCAN BLOCKED: Authorization required. Call signing::authorize_scan() before scanning. \
                This ensures banned users cannot access the scanner."
            ));
        }

        // Get the scan token for later signing
        let scan_token = crate::signing::get_scan_token()
            .ok_or_else(|| anyhow::anyhow!("No valid scan token. Re-authorize to continue."))?
            .clone();

        // Track which modules are actually used (for server validation during signing)
        let mut modules_used: Vec<String> = Vec::new();

        // Runtime state verification (anti-tampering)
        if !crate::license::verify_rt_state() {
            return Err(anyhow::anyhow!("Scanner integrity check failed. Please reinstall or contact info@bountyy.fi"));
        }

        // Increment scan counter for tracking
        crate::license::increment_scan_counter();

        // Clone job fields to owned types to fix Send lifetime issues
        let scan_id = job.scan_id.clone();
        let target = job.target.clone();
        let config = job.config.clone();

        info!("Starting scan for target: {}", target);

        let mut all_vulnerabilities: Vec<Vulnerability> = Vec::new();
        let mut total_tests: u64 = 0;

        // Phase 0: Crawl & Reconnaissance
        info!("[Phase 0] Starting reconnaissance crawl");
        let crawler = WebCrawler::new(Arc::clone(&self.http_client), 3, 50);
        let mut crawl_results = crawler.crawl(&target).await.unwrap_or_else(|e| {
            warn!("Crawler failed: {}, using fallback discovery", e);
            CrawlResults::new()
        });

        // JavaScript Mining for SPA attack surface discovery
        info!("[Phase 0] Mining JavaScript for API endpoints and parameters");
        let js_miner_results = self.js_miner_scanner.scan_full(&target, &config).await?;

        // Merge JS miner findings into crawl_results
        if !js_miner_results.api_endpoints.is_empty() || !js_miner_results.parameters.is_empty() {
            info!("[JS-Miner] Discovered {} API endpoints, {} parameter sets from JavaScript",
                  js_miner_results.api_endpoints.len(),
                  js_miner_results.parameters.len());

            // Add API endpoints
            crawl_results.api_endpoints.extend(js_miner_results.api_endpoints.clone());

            // Add form actions
            for action in js_miner_results.form_actions {
                crawl_results.api_endpoints.insert(action);
            }

            // Add parameters - merge into crawl_results.parameters
            for (endpoint, params) in js_miner_results.parameters {
                crawl_results.parameters
                    .entry(endpoint)
                    .or_insert_with(std::collections::HashSet::new)
                    .extend(params);
            }

            // Add GraphQL endpoints for later testing
            for gql_endpoint in &js_miner_results.graphql_endpoints {
                crawl_results.api_endpoints.insert(gql_endpoint.clone());
            }
        }

        // Store JS miner vulnerabilities (will be added later with other findings)
        let js_miner_vulns = js_miner_results.vulnerabilities;
        let js_miner_tests = js_miner_results.tests_run;

        // Framework & Technology Detection
        info!("[Tech] Detecting frameworks and technologies");
        let detector = FrameworkDetector::new(Arc::clone(&self.http_client));
        let detected_tech = detector.detect(&target).await.unwrap_or_else(|e| {
            warn!("Framework detection failed: {}", e);
            HashSet::new()
        });

        info!("[SUCCESS] Detected technologies:");
        for tech in &detected_tech {
            info!("   - {} ({:?}) [confidence: {:?}]",
                tech.name, tech.category, tech.confidence);
        }

        // Subdomain enumeration (if enabled via config or scan config)
        let mut discovered_subdomains = Vec::new();
        if self.config.subdomain_enum_enabled || config.enum_subdomains {
            info!("[Subdomain] Starting subdomain enumeration");

            // Extract domain from target URL
            if let Ok(parsed_url) = url::Url::parse(&target) {
                if let Some(domain_str) = parsed_url.host_str() {
                    // Convert to owned String to avoid lifetime issues
                    let domain = domain_str.to_string();
                    let thorough = self.config.subdomain_enum_thorough || config.scan_mode == ScanMode::Thorough || config.scan_mode == ScanMode::Insane;

                    match self.subdomain_enumerator.enumerate(&domain, thorough).await {
                        Ok(subdomains) => {
                            info!("[SUCCESS] Found {} subdomains", subdomains.len());

                            // Generate findings for discovered subdomains
                            let subdomain_findings = self.subdomain_enumerator
                                .generate_findings(&subdomains, &domain);
                            all_vulnerabilities.extend(subdomain_findings);

                            // Collect accessible subdomain URLs for further scanning
                            for (subdomain, _info) in &subdomains {
                                // Verify HTTP/HTTPS access
                                if let Some(accessible_url) = self.subdomain_enumerator
                                    .verify_http_access(subdomain).await
                                {
                                    discovered_subdomains.push(accessible_url);
                                }
                            }

                            info!("[SUCCESS] {} subdomains are accessible via HTTP/HTTPS",
                                  discovered_subdomains.len());
                        }
                        Err(e) => {
                            warn!("Subdomain enumeration failed: {}", e);
                        }
                    }
                }
            }
        } else {
            info!("[WARNING]  Subdomain enumeration disabled (set SUBDOMAIN_ENUM_ENABLED=true to enable)");
        }

        // Phase 2 Optimization: CDN Detection
        let cdn_info = if self.config.cdn_detection_enabled {
            self.detect_cdn(&target).await?
        } else {
            None
        };

        // Parse target URL to extract parameters
        let url_data = self.parse_target_url(&target)?;

        // Determine which parameters to test - PRIORITIZE DISCOVERED PARAMETERS
        let mut test_parameters: Vec<(String, String)> = Vec::new();

        // 1. Use parameters from crawled forms (HIGHEST PRIORITY)
        let discovered_params = crawl_results.get_all_parameters();
        if !discovered_params.is_empty() {
            info!("[TARGET] Using {} parameters discovered from forms", discovered_params.len());
            for param in discovered_params {
                test_parameters.push((param.clone(), "test".to_string()));
            }
        }

        // 2. Use parameters from URL query strings
        if !url_data.parameters.is_empty() {
            info!("[TARGET] Adding {} parameters from URL", url_data.parameters.len());
            test_parameters.extend(url_data.parameters.clone());
        }

        // 3. Fallback to common parameter names if nothing discovered
        if test_parameters.is_empty() {
            info!("[WARNING]  No parameters discovered - testing common parameter names");
            test_parameters = vec![
                ("id".to_string(), "1".to_string()),
                ("q".to_string(), "test".to_string()),
                ("search".to_string(), "test".to_string()),
                ("query".to_string(), "test".to_string()),
                ("page".to_string(), "1".to_string()),
                ("user".to_string(), "test".to_string()),
                ("name".to_string(), "test".to_string()),
                ("url".to_string(), "http://example.com".to_string()),
            ];
        }

        // Phase 1: Test URL parameters (or common parameter names if none exist)
        if !test_parameters.is_empty() {
            // Filter out irrelevant parameters (JS framework internals, etc.)
            let original_count = test_parameters.len();
            test_parameters.retain(|(name, _)| Self::is_relevant_parameter(name));
            let filtered_count = original_count - test_parameters.len();
            if filtered_count > 0 {
                info!("[FILTER] Skipped {} irrelevant parameters (framework internals)", filtered_count);
            }

            info!("Testing {} parameters for injection vulnerabilities", test_parameters.len());

            for (param_name, _param_value) in &test_parameters {
                // Early termination check
                if self.should_terminate_early(&all_vulnerabilities) {
                    break;
                }

                // XSS Testing
                let (xss_vulns, xss_tests) = self.xss_scanner
                    .scan_parameter(&target, param_name, &config)
                    .await?;
                all_vulnerabilities.extend(xss_vulns);
                total_tests += xss_tests as u64;

                // Update progress
                queue.increment_tests(scan_id.clone(), xss_tests as u64).await?;

                // SQLi Testing (skip if CDN protected) - Unified scanner with all techniques
                if !self.should_skip_scanner("sqli", &cdn_info) {
                    let (sqli_vulns, sqli_tests) = self.sqli_scanner
                        .scan_parameter(&target, param_name, &config)
                        .await?;
                    all_vulnerabilities.extend(sqli_vulns);
                    total_tests += sqli_tests as u64;
                    queue.increment_tests(scan_id.clone(), sqli_tests as u64).await?;
                }

                // Command Injection Testing (skip if CDN protected)
                if !self.should_skip_scanner("command_injection", &cdn_info) {
                    let (cmdi_vulns, cmdi_tests) = self.cmdi_scanner
                        .scan_parameter(&target, param_name, &config)
                        .await?;
                    all_vulnerabilities.extend(cmdi_vulns);
                    total_tests += cmdi_tests as u64;

                    queue.increment_tests(scan_id.clone(), cmdi_tests as u64).await?;
                }

                // Path Traversal Testing (skip if CDN protected)
                if !self.should_skip_scanner("path_traversal", &cdn_info) {
                    let (path_vulns, path_tests) = self.path_scanner
                        .scan_parameter(&target, param_name, &config)
                        .await?;
                    all_vulnerabilities.extend(path_vulns);
                    total_tests += path_tests as u64;

                    queue.increment_tests(scan_id.clone(), path_tests as u64).await?;
                }

                // SSRF Testing
                let (ssrf_vulns, ssrf_tests) = self.ssrf_scanner
                    .scan_parameter(&target, param_name, &config)
                    .await?;
                all_vulnerabilities.extend(ssrf_vulns);
                total_tests += ssrf_tests as u64;

                queue.increment_tests(scan_id.clone(), ssrf_tests as u64).await?;

                // Blind SSRF with OOB Callback Testing
                let (ssrf_blind_vulns, ssrf_blind_tests) = self.ssrf_blind_scanner
                    .scan_parameter(&target, param_name, &config)
                    .await?;
                all_vulnerabilities.extend(ssrf_blind_vulns);
                total_tests += ssrf_blind_tests as u64;
                queue.increment_tests(scan_id.clone(), ssrf_blind_tests as u64).await?;

                // NoSQL Injection Testing (skip if CDN protected)
                if !self.should_skip_scanner("nosql", &cdn_info) {
                    let (nosql_vulns, nosql_tests) = self.nosql_scanner
                        .scan_parameter(&target, param_name, &config)
                        .await?;
                    all_vulnerabilities.extend(nosql_vulns);
                    total_tests += nosql_tests as u64;

                    queue.increment_tests(scan_id.clone(), nosql_tests as u64).await?;
                }

                // XXE Testing (skip if CDN protected)
                if !self.should_skip_scanner("xxe", &cdn_info) {
                    let (xxe_vulns, xxe_tests) = self.xxe_scanner
                        .scan_parameter(&target, param_name, &config)
                        .await?;
                    all_vulnerabilities.extend(xxe_vulns);
                    total_tests += xxe_tests as u64;

                    queue.increment_tests(scan_id.clone(), xxe_tests as u64).await?;
                }

                // ReDoS Testing
                let (redos_vulns, redos_tests) = self.redos_scanner
                    .scan_parameter(&target, param_name, &config)
                    .await?;
                all_vulnerabilities.extend(redos_vulns);
                total_tests += redos_tests as u64;

                queue.increment_tests(scan_id.clone(), redos_tests as u64).await?;
            }
        }

        // Phase 1b: Test discovered API endpoints from JavaScript
        let api_endpoints: Vec<String> = crawl_results.api_endpoints.iter().cloned().collect();
        if !api_endpoints.is_empty() {
            info!("[Phase 1b] Testing {} API endpoints discovered from JavaScript", api_endpoints.len());

            // Get parameters to test on endpoints (from JS discovery, filtered)
            let js_params: Vec<String> = crawl_results.parameters
                .get("*")
                .map(|p| p.iter()
                    .filter(|name| Self::is_relevant_parameter(name))
                    .cloned()
                    .collect())
                .unwrap_or_default();

            // Test up to 10 API endpoints with discovered parameters
            for endpoint in api_endpoints.iter().take(10) {
                // Skip GraphQL endpoints (handled separately by GraphQL scanner)
                if endpoint.to_lowercase().contains("graphql") {
                    continue;
                }

                // Build full URL if endpoint is relative
                let full_url = if endpoint.starts_with("http") {
                    endpoint.clone()
                } else if let Ok(base) = url::Url::parse(&target) {
                    base.join(endpoint).map(|u| u.to_string()).unwrap_or_else(|_| {
                        format!("{}{}", target.trim_end_matches('/'), endpoint)
                    })
                } else {
                    format!("{}{}", target.trim_end_matches('/'), endpoint)
                };

                info!("[API-Test] Testing endpoint: {}", full_url);

                // Test with JS-discovered parameters (limit to 10)
                for param in js_params.iter().take(10) {
                    if self.should_terminate_early(&all_vulnerabilities) {
                        break;
                    }

                    // XSS on API endpoint
                    let (xss_vulns, xss_tests) = self.xss_scanner
                        .scan_parameter(&full_url, param, &config)
                        .await?;
                    all_vulnerabilities.extend(xss_vulns);
                    total_tests += xss_tests as u64;
                    queue.increment_tests(scan_id.clone(), xss_tests as u64).await?;

                    // SQLi on API endpoint
                    if !self.should_skip_scanner("sqli", &cdn_info) {
                        let (sqli_vulns, sqli_tests) = self.sqli_scanner
                            .scan_parameter(&full_url, param, &config)
                            .await?;
                        all_vulnerabilities.extend(sqli_vulns);
                        total_tests += sqli_tests as u64;
                        queue.increment_tests(scan_id.clone(), sqli_tests as u64).await?;
                    }
                }

                // Also test with common API parameters
                for param in &["id", "user_id", "email", "query", "search", "filter", "sort"] {
                    if self.should_terminate_early(&all_vulnerabilities) {
                        break;
                    }

                    let (xss_vulns, xss_tests) = self.xss_scanner
                        .scan_parameter(&full_url, param, &config)
                        .await?;
                    all_vulnerabilities.extend(xss_vulns);
                    total_tests += xss_tests as u64;
                    queue.increment_tests(scan_id.clone(), xss_tests as u64).await?;
                }
            }
        }

        // Early termination check after parameter scanning
        if self.should_terminate_early(&all_vulnerabilities) {
            let critical_count = all_vulnerabilities
                .iter()
                .filter(|v| v.severity == Severity::Critical)
                .count();

            warn!("[STOP]  Scan terminated early: {} critical vulnerabilities found", critical_count);
            warn!("[WARNING]  INCOMPLETE SCAN: Some vulnerabilities may have been missed!");

            let elapsed = start_time.elapsed();
            let license_sig = crate::license::get_license_signature();

            let mut results = ScanResults {
                scan_id: scan_id.clone(),
                target: target.clone(),
                tests_run: total_tests,
                vulnerabilities: all_vulnerabilities,
                started_at,
                completed_at: chrono::Utc::now().to_rfc3339(),
                duration_seconds: elapsed.as_secs_f64(),
                early_terminated: true,
                termination_reason: Some(format!(
                    "Scan stopped early after finding {} critical vulnerabilities. Enable comprehensive scanning for full results.",
                    critical_count
                )),
                scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                license_signature: Some(license_sig),
                quantum_signature: None,
                authorization_token_id: Some(scan_token.token.clone()),
            };

            // Sign even early-terminated results
            // STRICT MODE: Server signature required
            // Note: modules_used is empty for early termination
            if let Ok(results_hash) = crate::signing::hash_results(&results) {
                match crate::signing::sign_results(
                    &results_hash,
                    &scan_token,
                    vec![], // No modules used in early termination
                    Some(crate::signing::ScanMetadata {
                        targets_count: Some(1),
                        scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                        scan_duration_ms: Some(elapsed.as_millis() as u64),
                    }),
                ).await {
                    Ok(signature) => {
                        results.quantum_signature = Some(signature);
                    }
                    Err(e) => {
                        // STRICT MODE: Signing failure is fatal
                        return Err(anyhow::anyhow!("Failed to sign early-terminated results: {}", e));
                    }
                }
            }

            return Ok(results);
        }

        // Security Headers Check (Free tier)
        info!("Checking security headers");
        modules_used.push(crate::modules::ids::free::SECURITY_HEADERS.to_string());
        let (header_vulns, header_tests) = self.security_headers_scanner
            .scan(&target, &config)
            .await?;
        all_vulnerabilities.extend(header_vulns);
        total_tests += header_tests as u64;
        queue.increment_tests(scan_id.clone(), header_tests as u64).await?;

        // CORS Configuration Check (Free tier)
        info!("Checking CORS configuration");
        modules_used.push(crate::modules::ids::free::CORS_BASIC.to_string());
        let (cors_vulns, cors_tests) = self.cors_scanner
            .scan(&target, &config)
            .await?;
        all_vulnerabilities.extend(cors_vulns);
        total_tests += cors_tests as u64;
        queue.increment_tests(scan_id.clone(), cors_tests as u64).await?;

        // CSRF Protection Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CSRF_SCANNER) {
            info!("Checking CSRF protection");
            modules_used.push(crate::modules::ids::advanced_scanning::CSRF_SCANNER.to_string());
            let (csrf_vulns, csrf_tests) = self.csrf_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(csrf_vulns);
            total_tests += csrf_tests as u64;
            queue.increment_tests(scan_id.clone(), csrf_tests as u64).await?;
        }

        // GraphQL API Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::GRAPHQL_SCANNER) {
            info!("Checking GraphQL API security");
            modules_used.push(crate::modules::ids::advanced_scanning::GRAPHQL_SCANNER.to_string());
            let (graphql_vulns, graphql_tests) = self.graphql_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(graphql_vulns);
            total_tests += graphql_tests as u64;
            queue.increment_tests(scan_id.clone(), graphql_tests as u64).await?;
        }

        // OAuth 2.0 Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::OAUTH_SCANNER) {
            info!("Checking OAuth 2.0 security");
            modules_used.push(crate::modules::ids::advanced_scanning::OAUTH_SCANNER.to_string());
            let (oauth_vulns, oauth_tests) = self.oauth_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(oauth_vulns);
            total_tests += oauth_tests as u64;
            queue.increment_tests(scan_id.clone(), oauth_tests as u64).await?;
        }

        // SAML Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SAML_SCANNER) {
            info!("Checking SAML security");
            modules_used.push(crate::modules::ids::advanced_scanning::SAML_SCANNER.to_string());
            let (saml_vulns, saml_tests) = self.saml_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(saml_vulns);
            total_tests += saml_tests as u64;
            queue.increment_tests(scan_id.clone(), saml_tests as u64).await?;
        }

        // WebSocket Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::WEBSOCKET_SCANNER) {
            info!("Checking WebSocket security");
            modules_used.push(crate::modules::ids::advanced_scanning::WEBSOCKET_SCANNER.to_string());
            let (websocket_vulns, websocket_tests) = self.websocket_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(websocket_vulns);
            total_tests += websocket_tests as u64;
            queue.increment_tests(scan_id.clone(), websocket_tests as u64).await?;
        }

        // gRPC Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::GRPC_SCANNER) {
            info!("Checking gRPC security");
            modules_used.push(crate::modules::ids::advanced_scanning::GRPC_SCANNER.to_string());
            let (grpc_vulns, grpc_tests) = self.grpc_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(grpc_vulns);
            total_tests += grpc_tests as u64;
            queue.increment_tests(scan_id.clone(), grpc_tests as u64).await?;
        }

        // Authentication Bypass Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::AUTH_BYPASS) {
            info!("Checking authentication bypass");
            modules_used.push(crate::modules::ids::advanced_scanning::AUTH_BYPASS.to_string());
            let (auth_bypass_vulns, auth_bypass_tests) = self.auth_bypass_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(auth_bypass_vulns);
            total_tests += auth_bypass_tests as u64;
            queue.increment_tests(scan_id.clone(), auth_bypass_tests as u64).await?;
        }

        // Client Route Authorization Bypass Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CLIENT_ROUTE_AUTH_BYPASS) {
            info!("[ClientRouteAuth] Testing client-side route authorization bypass");
            modules_used.push(crate::modules::ids::advanced_scanning::CLIENT_ROUTE_AUTH_BYPASS.to_string());
            let (client_route_vulns, client_route_tests) = self.client_route_auth_bypass_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(client_route_vulns);
            total_tests += client_route_tests as u64;
            queue.increment_tests(scan_id.clone(), client_route_tests as u64).await?;
        }

        // Session Management Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SESSION_MANAGEMENT) {
            info!("Checking session management security");
            modules_used.push(crate::modules::ids::advanced_scanning::SESSION_MANAGEMENT.to_string());
            let (session_vulns, session_tests) = self.session_management_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(session_vulns);
            total_tests += session_tests as u64;
            queue.increment_tests(scan_id.clone(), session_tests as u64).await?;
        }

        // MFA Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::MFA_SCANNER) {
            info!("Checking MFA security");
            modules_used.push(crate::modules::ids::advanced_scanning::MFA_SCANNER.to_string());
            let (mfa_vulns, mfa_tests) = self.mfa_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(mfa_vulns);
            total_tests += mfa_tests as u64;
            queue.increment_tests(scan_id.clone(), mfa_tests as u64).await?;
        }

        // IDOR Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::IDOR_SCANNER) {
            info!("Checking for IDOR vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::IDOR_SCANNER.to_string());
            let (idor_vulns, idor_tests) = self.idor_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(idor_vulns);
            total_tests += idor_tests as u64;
            queue.increment_tests(scan_id.clone(), idor_tests as u64).await?;
        }

        // BOLA Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::BOLA_SCANNER) {
            info!("Checking for BOLA vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::BOLA_SCANNER.to_string());
            let (bola_vulns, bola_tests) = self.bola_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(bola_vulns);
            total_tests += bola_tests as u64;
            queue.increment_tests(scan_id.clone(), bola_tests as u64).await?;
        }

        // Authentication Manager Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::AUTH_MANAGER) {
            info!("Checking authentication management security");
            modules_used.push(crate::modules::ids::advanced_scanning::AUTH_MANAGER.to_string());
            let (auth_mgr_vulns, auth_mgr_tests) = self.auth_manager_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(auth_mgr_vulns);
            total_tests += auth_mgr_tests as u64;
            queue.increment_tests(scan_id.clone(), auth_mgr_tests as u64).await?;
        }

        // LDAP Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::LDAP_INJECTION) {
            info!("Checking for LDAP injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::LDAP_INJECTION.to_string());
            let (ldap_vulns, ldap_tests) = self.ldap_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(ldap_vulns);
            total_tests += ldap_tests as u64;
            queue.increment_tests(scan_id.clone(), ldap_tests as u64).await?;
        }

        // File Upload Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::FILE_UPLOAD) {
            info!("Checking file upload security");
            modules_used.push(crate::modules::ids::advanced_scanning::FILE_UPLOAD.to_string());
            let (upload_vulns, upload_tests) = self.file_upload_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(upload_vulns);
            total_tests += upload_tests as u64;
            queue.increment_tests(scan_id.clone(), upload_tests as u64).await?;
        }

        // Open Redirect Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::OPEN_REDIRECT) {
            info!("Checking for open redirect vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::OPEN_REDIRECT.to_string());
            let (redirect_vulns, redirect_tests) = self.open_redirect_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(redirect_vulns);
            total_tests += redirect_tests as u64;
            queue.increment_tests(scan_id.clone(), redirect_tests as u64).await?;
        }

        // Clickjacking Protection Check (Free tier)
        info!("Checking clickjacking protection");
        modules_used.push(crate::modules::ids::free::CLICKJACKING.to_string());
        let (clickjack_vulns, clickjack_tests) = self.clickjacking_scanner
            .scan(&target, &config)
            .await?;
        all_vulnerabilities.extend(clickjack_vulns);
        total_tests += clickjack_tests as u64;
        queue.increment_tests(scan_id.clone(), clickjack_tests as u64).await?;

        // CRLF Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CRLF_INJECTION) {
            info!("Checking for CRLF injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::CRLF_INJECTION.to_string());
            let (crlf_vulns, crlf_tests) = self.crlf_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(crlf_vulns);
            total_tests += crlf_tests as u64;
            queue.increment_tests(scan_id.clone(), crlf_tests as u64).await?;
        }

        // Email Header Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::EMAIL_HEADER_INJECTION) {
            info!("Checking for email header injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::EMAIL_HEADER_INJECTION.to_string());
            let (email_header_vulns, email_header_tests) = self.email_header_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(email_header_vulns);
            total_tests += email_header_tests as u64;
            queue.increment_tests(scan_id.clone(), email_header_tests as u64).await?;
        }

        // Template Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SSTI_SCANNER) {
            info!("Checking for template injection (SSTI) vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::SSTI_SCANNER.to_string());
            let (ssti_vulns, ssti_tests) = self.template_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(ssti_vulns);
            total_tests += ssti_tests as u64;
            queue.increment_tests(scan_id.clone(), ssti_tests as u64).await?;
        }

        // Deserialization Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::DESERIALIZATION) {
            info!("Checking for insecure deserialization vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::DESERIALIZATION.to_string());
            let (deser_vulns, deser_tests) = self.deserialization_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(deser_vulns);
            total_tests += deser_tests as u64;
            queue.increment_tests(scan_id.clone(), deser_tests as u64).await?;
        }

        // Prototype Pollution Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::PROTOTYPE_POLLUTION) {
            info!("Checking for prototype pollution vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::PROTOTYPE_POLLUTION.to_string());
            let (pp_vulns, pp_tests) = self.prototype_pollution_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(pp_vulns);
            total_tests += pp_tests as u64;
            queue.increment_tests(scan_id.clone(), pp_tests as u64).await?;
        }

        // API Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::API_SECURITY) {
            info!("Checking API security");
            modules_used.push(crate::modules::ids::advanced_scanning::API_SECURITY.to_string());
            let (api_vulns, api_tests) = self.api_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(api_vulns);
            total_tests += api_tests as u64;
            queue.increment_tests(scan_id.clone(), api_tests as u64).await?;
        }

        // HTTP Request Smuggling Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::HTTP_SMUGGLING) {
            info!("Checking for HTTP request smuggling vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::HTTP_SMUGGLING.to_string());
            let (smuggling_vulns, smuggling_tests) = self.http_smuggling_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(smuggling_vulns);
            total_tests += smuggling_tests as u64;
            queue.increment_tests(scan_id.clone(), smuggling_tests as u64).await?;
        }

        // XML Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::XML_INJECTION) {
            info!("Checking for XML injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::XML_INJECTION.to_string());
            let (xml_vulns, xml_tests) = self.xml_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(xml_vulns);
            total_tests += xml_tests as u64;
            queue.increment_tests(scan_id.clone(), xml_tests as u64).await?;
        }

        // XPath Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::XPATH_INJECTION) {
            info!("Checking for XPath injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::XPATH_INJECTION.to_string());
            let (xpath_vulns, xpath_tests) = self.xpath_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(xpath_vulns);
            total_tests += xpath_tests as u64;
            queue.increment_tests(scan_id.clone(), xpath_tests as u64).await?;
        }

        // Code Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CODE_INJECTION) {
            info!("Checking for code injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::CODE_INJECTION.to_string());
            let (code_vulns, code_tests) = self.code_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(code_vulns);
            total_tests += code_tests as u64;
            queue.increment_tests(scan_id.clone(), code_tests as u64).await?;
        }

        // SSI Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SSI_INJECTION) {
            info!("Checking for SSI injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::SSI_INJECTION.to_string());
            let (ssi_vulns, ssi_tests) = self.ssi_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(ssi_vulns);
            total_tests += ssi_tests as u64;
            queue.increment_tests(scan_id.clone(), ssi_tests as u64).await?;
        }

        // Race Condition Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::RACE_CONDITION) {
            info!("Checking for race condition vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::RACE_CONDITION.to_string());
            let (race_vulns, race_tests) = self.race_condition_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(race_vulns);
            total_tests += race_tests as u64;
            queue.increment_tests(scan_id.clone(), race_tests as u64).await?;
        }

        // Mass Assignment Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::MASS_ASSIGNMENT) {
            info!("Checking for mass assignment vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::MASS_ASSIGNMENT.to_string());
            let (ma_vulns, ma_tests) = self.mass_assignment_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(ma_vulns);
            total_tests += ma_tests as u64;
            queue.increment_tests(scan_id.clone(), ma_tests as u64).await?;
        }

        // Information Disclosure Security Check (Free tier)
        info!("Checking for information disclosure vulnerabilities");
        modules_used.push(crate::modules::ids::free::INFO_DISCLOSURE_BASIC.to_string());
        let (info_vulns, info_tests) = self.information_disclosure_scanner
            .scan(&target, &config)
            .await?;
        all_vulnerabilities.extend(info_vulns);
        total_tests += info_tests as u64;
        queue.increment_tests(scan_id.clone(), info_tests as u64).await?;

        // Host Header Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::HOST_HEADER_INJECTION) {
            info!("Checking for host header injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::HOST_HEADER_INJECTION.to_string());
            let (hhi_vulns, hhi_tests) = self.host_header_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(hhi_vulns);
            total_tests += hhi_tests as u64;
            queue.increment_tests(scan_id.clone(), hhi_tests as u64).await?;
        }

        // Cache Poisoning Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CACHE_POISONING) {
            info!("Checking for cache poisoning vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::CACHE_POISONING.to_string());
            let (cp_vulns, cp_tests) = self.cache_poisoning_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cp_vulns);
            total_tests += cp_tests as u64;
            queue.increment_tests(scan_id.clone(), cp_tests as u64).await?;
        }

        // Business Logic Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::BUSINESS_LOGIC) {
            info!("Checking for business logic vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::BUSINESS_LOGIC.to_string());
            let (bl_vulns, bl_tests) = self.business_logic_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(bl_vulns);
            total_tests += bl_tests as u64;
            queue.increment_tests(scan_id.clone(), bl_tests as u64).await?;
        }

        // JWT Vulnerabilities Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::JWT_SCANNER) {
            info!("Checking for JWT vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::JWT_SCANNER.to_string());
            let (jwt_vulns, jwt_tests) = self.jwt_vulnerabilities_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(jwt_vulns);
            total_tests += jwt_tests as u64;
            queue.increment_tests(scan_id.clone(), jwt_tests as u64).await?;
        }

        // GraphQL Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::GRAPHQL_SCANNER) {
            info!("Checking for GraphQL security issues");
            modules_used.push(crate::modules::ids::advanced_scanning::GRAPHQL_SCANNER.to_string());
            let (gql_vulns, gql_tests) = self.graphql_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(gql_vulns);
            total_tests += gql_tests as u64;
            queue.increment_tests(scan_id.clone(), gql_tests as u64).await?;
        }

        // NoSQL Injection Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::NOSQL_SCANNER) {
            info!("Checking for NoSQL injection vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::NOSQL_SCANNER.to_string());
            let (nosql_vulns, nosql_tests) = self.nosql_injection_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(nosql_vulns);
            total_tests += nosql_tests as u64;
            queue.increment_tests(scan_id.clone(), nosql_tests as u64).await?;
        }

        // File Upload Vulnerabilities Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::FILE_UPLOAD) {
            info!("Checking for file upload vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::FILE_UPLOAD.to_string());
            let (upload_vulns, upload_tests) = self.file_upload_vulnerabilities_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(upload_vulns);
            total_tests += upload_tests as u64;
            queue.increment_tests(scan_id.clone(), upload_tests as u64).await?;
        }

        // CORS Misconfiguration Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::CORS_MISCONFIG) {
            info!("Checking for CORS misconfiguration");
            modules_used.push(crate::modules::ids::advanced_scanning::CORS_MISCONFIG.to_string());
            let (cors_misc_vulns, cors_misc_tests) = self.cors_misconfiguration_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cors_misc_vulns);
            total_tests += cors_misc_tests as u64;
            queue.increment_tests(scan_id.clone(), cors_misc_tests as u64).await?;
        }

        // Cloud Storage Security Check (Team+)
        if scan_token.is_module_authorized(crate::modules::ids::cloud_scanning::CLOUD_STORAGE) {
            info!("Checking for cloud storage misconfigurations");
            modules_used.push(crate::modules::ids::cloud_scanning::CLOUD_STORAGE.to_string());
            let (cloud_vulns, cloud_tests) = self.cloud_storage_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cloud_vulns);
            total_tests += cloud_tests as u64;
            queue.increment_tests(scan_id.clone(), cloud_tests as u64).await?;
        }

        // Framework Vulnerabilities Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::FRAMEWORK_VULNS) {
            info!("Checking for framework-specific vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::FRAMEWORK_VULNS.to_string());
            let (framework_vulns, framework_tests) = self.framework_vulnerabilities_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(framework_vulns);
            total_tests += framework_tests as u64;
            queue.increment_tests(scan_id.clone(), framework_tests as u64).await?;
        }

        // JavaScript Mining Security Check (results from Phase 0)
        info!("[JS-Miner] Adding {} vulnerabilities found during reconnaissance", js_miner_vulns.len());
        all_vulnerabilities.extend(js_miner_vulns);
        total_tests += js_miner_tests as u64;
        queue.increment_tests(scan_id.clone(), js_miner_tests as u64).await?;

        // Sensitive Data Exposure Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SENSITIVE_DATA) {
            info!("Checking for sensitive data exposure");
            modules_used.push(crate::modules::ids::advanced_scanning::SENSITIVE_DATA.to_string());
            let (sensitive_vulns, sensitive_tests) = self.sensitive_data_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(sensitive_vulns);
            total_tests += sensitive_tests as u64;
            queue.increment_tests(scan_id.clone(), sensitive_tests as u64).await?;
        }

        // Advanced API Fuzzing (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::API_FUZZER) {
            info!("Running advanced API fuzzing");
            modules_used.push(crate::modules::ids::advanced_scanning::API_FUZZER.to_string());
            let (api_fuzz_vulns, api_fuzz_tests) = self.api_fuzzer_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(api_fuzz_vulns);
            total_tests += api_fuzz_tests as u64;
            queue.increment_tests(scan_id.clone(), api_fuzz_tests as u64).await?;
        }

        // API Gateway Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::API_GATEWAY) {
            info!("Checking API Gateway security");
            modules_used.push(crate::modules::ids::advanced_scanning::API_GATEWAY.to_string());
            let (apigw_vulns, apigw_tests) = self.api_gateway_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(apigw_vulns);
            total_tests += apigw_tests as u64;
            queue.increment_tests(scan_id.clone(), apigw_tests as u64).await?;
        }

        // Cloud Security Check (Team+)
        if scan_token.is_module_authorized(crate::modules::ids::cloud_scanning::CLOUD_SECURITY) {
            info!("Checking cloud security vulnerabilities");
            modules_used.push(crate::modules::ids::cloud_scanning::CLOUD_SECURITY.to_string());
            let (cloud_sec_vulns, cloud_sec_tests) = self.cloud_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cloud_sec_vulns);
            total_tests += cloud_sec_tests as u64;
            queue.increment_tests(scan_id.clone(), cloud_sec_tests as u64).await?;
        }

        // Container Security Check (Team+)
        if scan_token.is_module_authorized(crate::modules::ids::cloud_scanning::CONTAINER_SCANNER) {
            info!("Checking container security");
            modules_used.push(crate::modules::ids::cloud_scanning::CONTAINER_SCANNER.to_string());
            let (container_vulns, container_tests) = self.container_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(container_vulns);
            total_tests += container_tests as u64;
            queue.increment_tests(scan_id.clone(), container_tests as u64).await?;
        }

        // WebAuthn/FIDO2 Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::WEBAUTHN_SCANNER) {
            info!("Checking WebAuthn/FIDO2 security");
            modules_used.push(crate::modules::ids::advanced_scanning::WEBAUTHN_SCANNER.to_string());
            let (webauthn_vulns, webauthn_tests) = self.webauthn_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(webauthn_vulns);
            total_tests += webauthn_tests as u64;
            queue.increment_tests(scan_id.clone(), webauthn_tests as u64).await?;
        }

        // HTTP/3 & QUIC Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::HTTP3_SCANNER) {
            info!("Checking HTTP/3 and QUIC security");
            modules_used.push(crate::modules::ids::advanced_scanning::HTTP3_SCANNER.to_string());
            let (http3_vulns, http3_tests) = self.http3_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(http3_vulns);
            total_tests += http3_tests as u64;
            queue.increment_tests(scan_id.clone(), http3_tests as u64).await?;
        }

        // Advanced SSTI Security Check (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::SSTI_ADVANCED) {
            info!("Checking advanced SSTI vulnerabilities");
            modules_used.push(crate::modules::ids::advanced_scanning::SSTI_ADVANCED.to_string());
            let (ssti_adv_vulns, ssti_adv_tests) = self.ssti_advanced_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(ssti_adv_vulns);
            total_tests += ssti_adv_tests as u64;
            queue.increment_tests(scan_id.clone(), ssti_adv_tests as u64).await?;
        }

        // CVE-2025-55182: React Server Components RCE (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::cve_scanners::CVE_2025_55182) {
            info!("Checking for CVE-2025-55182 (React2Shell RCE)");
            modules_used.push(crate::modules::ids::cve_scanners::CVE_2025_55182.to_string());
            let (cve_55182_vulns, cve_55182_tests) = self.cve_2025_55182_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cve_55182_vulns);
            total_tests += cve_55182_tests as u64;
            queue.increment_tests(scan_id.clone(), cve_55182_tests as u64).await?;
        }

        // CVE-2025-55183: React Server Components Source Code Exposure (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::cve_scanners::CVE_2025_55183) {
            info!("Checking for CVE-2025-55183 (RSC Source Code Exposure)");
            modules_used.push(crate::modules::ids::cve_scanners::CVE_2025_55183.to_string());
            let (cve_55183_vulns, cve_55183_tests) = self.cve_2025_55183_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cve_55183_vulns);
            total_tests += cve_55183_tests as u64;
            queue.increment_tests(scan_id.clone(), cve_55183_tests as u64).await?;
        }

        // CVE-2025-55184: React Server Components DoS (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::cve_scanners::CVE_2025_55184) {
            info!("Checking for CVE-2025-55184 (RSC DoS)");
            modules_used.push(crate::modules::ids::cve_scanners::CVE_2025_55184.to_string());
            let (cve_55184_vulns, cve_55184_tests) = self.cve_2025_55184_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(cve_55184_vulns);
            total_tests += cve_55184_tests as u64;
            queue.increment_tests(scan_id.clone(), cve_55184_tests as u64).await?;
        }

        // HTTP Parameter Pollution (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::HPP_SCANNER) {
            info!("[HPP] Testing for HTTP Parameter Pollution");
            modules_used.push(crate::modules::ids::advanced_scanning::HPP_SCANNER.to_string());
            let (hpp_vulns, hpp_tests) = self.hpp_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(hpp_vulns);
            total_tests += hpp_tests as u64;
            queue.increment_tests(scan_id.clone(), hpp_tests as u64).await?;
        }

        // WAF Bypass Testing (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::WAF_BYPASS) {
            info!("[WAF-Bypass] Testing advanced WAF bypass techniques");
            modules_used.push(crate::modules::ids::advanced_scanning::WAF_BYPASS.to_string());
            let (waf_vulns, waf_tests) = self.waf_bypass_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(waf_vulns);
            total_tests += waf_tests as u64;
            queue.increment_tests(scan_id.clone(), waf_tests as u64).await?;
        }

        // Merlin - JavaScript Library Vulnerability Detection (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::MERLIN_SCANNER) {
            info!("[Merlin] Scanning for vulnerable JavaScript libraries");
            modules_used.push(crate::modules::ids::advanced_scanning::MERLIN_SCANNER.to_string());
            let (merlin_vulns, merlin_tests) = self.merlin_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(merlin_vulns);
            total_tests += merlin_tests as u64;
            queue.increment_tests(scan_id.clone(), merlin_tests as u64).await?;
        }

        // Tomcat Misconfiguration Scanner (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::TOMCAT_MISCONFIG) {
            info!("[Tomcat] Checking for Apache Tomcat misconfigurations");
            modules_used.push(crate::modules::ids::advanced_scanning::TOMCAT_MISCONFIG.to_string());
            let (tomcat_vulns, tomcat_tests) = self.tomcat_misconfig_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(tomcat_vulns);
            total_tests += tomcat_tests as u64;
            queue.increment_tests(scan_id.clone(), tomcat_tests as u64).await?;
        }

        // Varnish Misconfiguration Scanner (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::VARNISH_MISCONFIG) {
            info!("[Varnish] Checking for Varnish cache misconfigurations");
            modules_used.push(crate::modules::ids::advanced_scanning::VARNISH_MISCONFIG.to_string());
            let (varnish_vulns, varnish_tests) = self.varnish_misconfig_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(varnish_vulns);
            total_tests += varnish_tests as u64;
            queue.increment_tests(scan_id.clone(), varnish_tests as u64).await?;
        }

        // JavaScript Sensitive Information Leakage Scanner (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::JS_SENSITIVE_INFO) {
            info!("[JS-Sensitive] Scanning JavaScript for sensitive information leakage");
            modules_used.push(crate::modules::ids::advanced_scanning::JS_SENSITIVE_INFO.to_string());
            let (js_sensitive_vulns, js_sensitive_tests) = self.js_sensitive_info_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(js_sensitive_vulns);
            total_tests += js_sensitive_tests as u64;
            queue.increment_tests(scan_id.clone(), js_sensitive_tests as u64).await?;
        }

        // Rate Limiting Scanner (Professional+)
        if scan_token.is_module_authorized(crate::modules::ids::advanced_scanning::RATE_LIMITING) {
            info!("[RateLimit] Testing for insufficient rate limiting on authentication endpoints");
            modules_used.push(crate::modules::ids::advanced_scanning::RATE_LIMITING.to_string());
            let (rate_limit_vulns, rate_limit_tests) = self.rate_limiting_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(rate_limit_vulns);
            total_tests += rate_limit_tests as u64;
            queue.increment_tests(scan_id.clone(), rate_limit_tests as u64).await?;
        }

        // WordPress Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::WORDPRESS_SCANNER) {
            info!("[WordPress] Advanced WordPress security scanning");
            modules_used.push(crate::modules::ids::cms_security::WORDPRESS_SCANNER.to_string());
            let (wordpress_vulns, wordpress_tests) = self.wordpress_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(wordpress_vulns);
            total_tests += wordpress_tests as u64;
            queue.increment_tests(scan_id.clone(), wordpress_tests as u64).await?;
        } else {
            debug!("[WordPress] Module not authorized - skipping");
        }

        // Drupal Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::DRUPAL_SCANNER) {
            info!("[Drupal] Advanced Drupal security scanning");
            modules_used.push(crate::modules::ids::cms_security::DRUPAL_SCANNER.to_string());
            let (drupal_vulns, drupal_tests) = self.drupal_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(drupal_vulns);
            total_tests += drupal_tests as u64;
            queue.increment_tests(scan_id.clone(), drupal_tests as u64).await?;
        } else {
            debug!("[Drupal] Module not authorized - skipping");
        }

        // Laravel Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::LARAVEL_SCANNER) {
            info!("[Laravel] Advanced Laravel security scanning");
            modules_used.push(crate::modules::ids::cms_security::LARAVEL_SCANNER.to_string());
            let (laravel_vulns, laravel_tests) = self.laravel_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(laravel_vulns);
            total_tests += laravel_tests as u64;
            queue.increment_tests(scan_id.clone(), laravel_tests as u64).await?;
        } else {
            debug!("[Laravel] Module not authorized - skipping");
        }

        // Express.js Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::EXPRESS_SCANNER) {
            info!("[Express] Advanced Express.js/Node.js security scanning");
            modules_used.push(crate::modules::ids::cms_security::EXPRESS_SCANNER.to_string());
            let (express_vulns, express_tests) = self.express_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(express_vulns);
            total_tests += express_tests as u64;
            queue.increment_tests(scan_id.clone(), express_tests as u64).await?;
        } else {
            debug!("[Express] Module not authorized - skipping");
        }

        // Next.js Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::NEXTJS_SCANNER) {
            info!("[Next.js] Advanced Next.js security scanning");
            modules_used.push(crate::modules::ids::cms_security::NEXTJS_SCANNER.to_string());
            let (nextjs_vulns, nextjs_tests) = self.nextjs_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(nextjs_vulns);
            total_tests += nextjs_tests as u64;
            queue.increment_tests(scan_id.clone(), nextjs_tests as u64).await?;
        } else {
            debug!("[Next.js] Module not authorized - skipping");
        }

        // SvelteKit Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::SVELTEKIT_SCANNER) {
            info!("[SvelteKit] Advanced SvelteKit security scanning");
            modules_used.push(crate::modules::ids::cms_security::SVELTEKIT_SCANNER.to_string());
            let (sveltekit_vulns, sveltekit_tests) = self.sveltekit_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(sveltekit_vulns);
            total_tests += sveltekit_tests as u64;
            queue.increment_tests(scan_id.clone(), sveltekit_tests as u64).await?;
        } else {
            debug!("[SvelteKit] Module not authorized - skipping");
        }

        // React Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::REACT_SCANNER) {
            info!("[React] Advanced React security scanning");
            modules_used.push(crate::modules::ids::cms_security::REACT_SCANNER.to_string());
            let (react_vulns, react_tests) = self.react_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(react_vulns);
            total_tests += react_tests as u64;
            queue.increment_tests(scan_id.clone(), react_tests as u64).await?;
        } else {
            debug!("[React] Module not authorized - skipping");
        }

        // Django Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::DJANGO_SCANNER) {
            info!("[Django] Advanced Django security scanning");
            modules_used.push(crate::modules::ids::cms_security::DJANGO_SCANNER.to_string());
            let (django_vulns, django_tests) = self.django_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(django_vulns);
            total_tests += django_tests as u64;
            queue.increment_tests(scan_id.clone(), django_tests as u64).await?;
        } else {
            debug!("[Django] Module not authorized - skipping");
        }

        // Liferay Security Scanner (Personal+ license)
        if scan_token.is_module_authorized(crate::modules::ids::cms_security::LIFERAY_SCANNER) {
            info!("[Liferay] Advanced Liferay security scanning");
            modules_used.push(crate::modules::ids::cms_security::LIFERAY_SCANNER.to_string());
            let (liferay_vulns, liferay_tests) = self.liferay_security_scanner
                .scan(&target, &config)
                .await?;
            all_vulnerabilities.extend(liferay_vulns);
            total_tests += liferay_tests as u64;
            queue.increment_tests(scan_id.clone(), liferay_tests as u64).await?;
        } else {
            debug!("[Liferay] Module not authorized - skipping");
        }

        // Phase 2: Crawler (if enabled)
        if config.enable_crawler {
            info!("Crawler enabled - discovering additional endpoints");
            match self.crawl_target(&target, config.max_depth).await {
                Ok(discovered_urls) => {
                    info!("Crawler discovered {} additional URLs", discovered_urls.len());
                    for discovered_url in discovered_urls {
                        let url_data = match self.parse_target_url(&discovered_url) {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Failed to parse discovered URL {}: {}", discovered_url, e);
                                continue;
                            }
                        };

                        for (param_name, _) in &url_data.parameters {
                            let (vulns, tests) = self.xss_scanner
                                .scan_parameter(&discovered_url, param_name, &config)
                                .await?;
                            all_vulnerabilities.extend(vulns);
                            total_tests += tests as u64;
                            queue.increment_tests(scan_id.clone(), tests as u64).await?;
                        }
                    }
                }
                Err(e) => {
                    warn!("Crawler failed: {}", e);
                }
            }
        }

        // Phase 3: Ultra mode - Additional attack vectors
        if config.scan_mode == ScanMode::Thorough || config.scan_mode == ScanMode::Insane {
            info!("Thorough/Insane mode enabled - testing advanced attack vectors");

            // Note: Time-based blind SQLi is now automatically included in the unified scanner

            // Test for SSRF vulnerabilities
            let ssrf_result = self.test_ssrf(&target, &url_data.parameters).await;
            if let Ok((ssrf_vulns, ssrf_tests)) = ssrf_result {
                all_vulnerabilities.extend(ssrf_vulns);
                total_tests += ssrf_tests as u64;
                queue.increment_tests(scan_id.clone(), ssrf_tests as u64).await?;
            }
        }

        let elapsed = start_time.elapsed();

        info!(
            "Scan completed: {} vulnerabilities found in {} tests ({:.2}s)",
            all_vulnerabilities.len(),
            total_tests,
            elapsed.as_secs_f64()
        );

        // Embed license signature in results for audit trail (legacy)
        let license_sig = crate::license::get_license_signature();

        // Create preliminary results for hashing
        let mut results = ScanResults {
            scan_id: scan_id.clone(),
            target: target.clone(),
            tests_run: total_tests,
            vulnerabilities: all_vulnerabilities,
            started_at,
            completed_at: chrono::Utc::now().to_rfc3339(),
            duration_seconds: elapsed.as_secs_f64(),
            early_terminated: false,
            termination_reason: None,
            scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            license_signature: Some(license_sig),
            quantum_signature: None,
            authorization_token_id: Some(scan_token.token.clone()),
        };

        // ============================================================
        // QUANTUM-SAFE SIGNING - MANDATORY FOR ALL RESULTS
        // ============================================================
        // Sign the results with the scan token to prove authenticity.
        // This creates a cryptographic audit trail that cannot be forged.
        // STRICT MODE: Server signature required - no unsigned results allowed.
        let results_hash = crate::signing::hash_results(&results)
            .map_err(|e| anyhow::anyhow!("Failed to hash results: {}", e))?;

        info!("[Signing] Signing results with {} modules used", modules_used.len());
        match crate::signing::sign_results(
            &results_hash,
            &scan_token,
            modules_used,
            Some(crate::signing::ScanMetadata {
                targets_count: Some(1),
                scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                scan_duration_ms: Some(elapsed.as_millis() as u64),
            }),
        ).await {
            Ok(signature) => {
                info!("[SIGNED] Results signed with algorithm: {}", signature.algorithm);
                results.quantum_signature = Some(signature);
            }
            Err(crate::signing::SigningError::ServerUnreachable(msg)) => {
                // STRICT MODE: Signing requires server connection
                error!("Failed to sign results - server unreachable: {}", msg);
                return Err(anyhow::anyhow!("Signing server unreachable: {}", msg));
            }
            Err(e) => {
                // STRICT MODE: No unsigned results allowed
                error!("Failed to sign results: {}", e);
                return Err(anyhow::anyhow!("Failed to sign results: {}", e));
            }
        }

        Ok(results)
    }

    /// Detect if target is behind a CDN
    async fn detect_cdn(&self, target: &str) -> Result<Option<String>> {
        use crate::cdn_detector;

        debug!("Checking CDN protection for: {}", target);

        match self.http_client.get(target).await {
            Ok(response) => {
                if let Some(cdn_name) = cdn_detector::is_cdn_protected(&response) {
                    info!("[CDN] CDN detected: {} - Optimizing scan strategy", cdn_name);
                    return Ok(Some(cdn_name));
                }
                Ok(None)
            },
            Err(_) => {
                // If initial request fails, proceed without CDN detection
                Ok(None)
            }
        }
    }

    /// Check if a parameter name is relevant for security testing
    /// Filters out JavaScript framework internals, crypto libraries, and other noise
    fn is_relevant_parameter(param_name: &str) -> bool {
        let param_lower = param_name.to_lowercase();

        // Skip parameters starting with underscore (usually internal/private)
        if param_name.starts_with('_') {
            return false;
        }

        // Skip UUID-like parameters (f_xxx, generated IDs)
        if param_name.starts_with("f_") && param_name.len() > 10 {
            return false;
        }

        // Skip Vue.js / Nuxt internals
        let vue_internals = [
            "vnode", "scopedslots", "vuesignature", "vuex", "vuecomponent",
            "$attrs", "$listeners", "$slots", "$refs", "$el", "$options",
        ];
        if vue_internals.iter().any(|v| param_lower == *v) {
            return false;
        }

        // Skip Apollo GraphQL internals
        let apollo_internals = [
            "apollo", "apollopromises", "apolloinitdata", "apolloprovider",
            "apolloutil", "apolloclients", "apollostate",
        ];
        if apollo_internals.iter().any(|a| param_lower.contains(a)) {
            return false;
        }

        // Skip Sentry monitoring internals
        if param_lower.contains("sentry") {
            return false;
        }

        // Skip crypto library references
        let crypto_libs = [
            "elliptic", "secp256k1", "ripple", "ecdsa", "ed25519", "curve25519",
        ];
        if crypto_libs.iter().any(|c| param_lower == *c) {
            return false;
        }

        // Skip *Service, *Provider patterns (service references, not input params)
        if (param_lower.ends_with("service") || param_lower.ends_with("provider"))
            && param_name.len() > 10 {
            return false;
        }

        // Skip common JS framework internals
        let framework_internals = [
            "morph", "prefetch", "deep", "intersection", "wrapper",
            "tune", "palette", "scroll", "live", "normal", "alarm",
            "mutation", "getmetahtml", "routename", "checkoutparams",
        ];
        if framework_internals.iter().any(|f| param_lower == *f) {
            return false;
        }

        true
    }

    /// Check if we should skip a scanner based on CDN detection
    fn should_skip_scanner(&self, scanner_name: &str, cdn_info: &Option<String>) -> bool {
        if !self.config.cdn_detection_enabled {
            return false;
        }

        if let Some(_cdn_name) = cdn_info {
            use crate::cdn_detector::get_scanners_to_skip_for_cdn;
            let skip_list = get_scanners_to_skip_for_cdn(_cdn_name);
            if skip_list.contains(&scanner_name.to_string()) {
                debug!("[Skip] Skipping {} (CDN-protected)", scanner_name);
                return true;
            }
        }
        false
    }

    /// Check if we should terminate early due to critical vulnerabilities
    fn should_terminate_early(&self, vulnerabilities: &[Vulnerability]) -> bool {
        if !self.config.early_termination_enabled {
            return false;
        }

        let critical_count = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();

        if critical_count > 0 {
            warn!("[ALERT] Early termination: {} critical vulnerabilities found", critical_count);
            true
        } else {
            false
        }
    }

    /// Parse target URL and extract parameters
    fn parse_target_url(&self, target: &str) -> Result<UrlData> {
        let parsed = url::Url::parse(target)
            .context("Failed to parse target URL")?;

        let mut parameters = Vec::new();

        // Extract query parameters
        for (name, value) in parsed.query_pairs() {
            parameters.push((name.to_string(), value.to_string()));
        }

        let scheme = parsed.scheme().to_string();
        let host = parsed.host_str().unwrap_or("").to_string();
        let path = parsed.path().to_string();

        Ok(UrlData {
            base_url: format!("{}://{}{}", scheme, host, path),
            parameters,
        })
    }

    /// Crawl target to discover additional URLs
    async fn crawl_target(&self, start_url: &str, max_depth: u32) -> Result<Vec<String>> {
        use regex::Regex;
        use std::collections::HashSet;

        let mut discovered = HashSet::new();
        let mut to_visit = vec![(start_url.to_string(), 0u32)];
        let mut visited = HashSet::new();

        let parsed_start = url::Url::parse(start_url)?;
        let base_domain = parsed_start.host_str().unwrap_or("").to_string();
        let scheme = parsed_start.scheme().to_string();

        let link_regex = Regex::new(r#"href=["']([^"']+)["']"#)?;

        while let Some((current_url, depth)) = to_visit.pop() {
            if depth >= max_depth || visited.contains(&current_url) {
                continue;
            }

            visited.insert(current_url.clone());

            match self.http_client.get(&current_url).await {
                Ok(response) => {
                    // Extract links from HTML
                    for cap in link_regex.captures_iter(&response.body) {
                        if let Some(link) = cap.get(1) {
                            let link_string = link.as_str().to_string();

                            // Build absolute URL
                            let absolute_url = if link_string.starts_with("http") {
                                link_string.clone()
                            } else if link_string.starts_with('/') {
                                format!("{}://{}{}", &scheme, &base_domain, &link_string)
                            } else {
                                continue; // Skip relative URLs for now
                            };

                            // Only crawl same domain
                            if let Ok(parsed) = url::Url::parse(&absolute_url) {
                                if parsed.host_str() == Some(base_domain.as_str()) {
                                    discovered.insert(absolute_url.clone());
                                    if depth + 1 < max_depth {
                                        to_visit.push((absolute_url, depth + 1));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to crawl {}: {}", current_url, e);
                }
            }
        }

        Ok(discovered.into_iter().collect())
    }

    /// Test for SSRF (Server-Side Request Forgery) vulnerabilities
    async fn test_ssrf(
        &self,
        base_url: &str,
        parameters: &[(String, String)],
    ) -> Result<(Vec<Vulnerability>, usize)> {
        use crate::types::{Confidence, Severity};

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // SSRF test payloads - Convert to owned Strings to avoid &str lifetime issues across await
        let ssrf_payloads: Vec<String> = vec![
            "http://169.254.169.254/latest/meta-data/".to_string(),  // AWS metadata
            "http://metadata.google.internal/".to_string(),           // GCP metadata
            "http://localhost:80".to_string(),
            "http://127.0.0.1:22".to_string(),
            "http://0.0.0.0:3306".to_string(),
            "file:///etc/passwd".to_string(),
            "gopher://127.0.0.1:25/".to_string(),
        ];

        for (param_name, _) in parameters {
            for payload in &ssrf_payloads {
                tests_run += 1;

                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param_name, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param_name, urlencoding::encode(payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        // Check for SSRF indicators
                        let has_metadata = response.body.contains("ami-id")
                            || response.body.contains("instance-id")
                            || response.body.contains("meta-data");
                        let has_internal_response = response.body.contains("root:x:")
                            || response.body.contains("SSH-");

                        if has_metadata || has_internal_response {
                            info!("SSRF vulnerability detected in parameter '{}'", param_name);

                            let vuln = Vulnerability {
                                id: format!("ssrf_{}", uuid::Uuid::new_v4().to_string()),
                                vuln_type: "Server-Side Request Forgery (SSRF)".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "SSRF".to_string(),
                                url: test_url.clone(),
                                parameter: Some(param_name.clone()),
                                payload: payload.to_string(),
                                description: format!(
                                    "SSRF vulnerability detected in parameter '{}'. The application makes requests to attacker-controlled URLs.",
                                    param_name
                                ),
                                evidence: Some("Internal service response detected".to_string()),
                                cwe: "CWE-918".to_string(),
                                cvss: 9.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Validate and sanitize all URLs\n2. Use allowlists for permitted domains\n3. Disable unnecessary URL schemes (file://, gopher://)\n4. Implement network segmentation".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            };

                            vulnerabilities.push(vuln);
                            break; // Found SSRF, no need to test more payloads for this param
                        }
                    }
                    Err(e) => {
                        debug!("SSRF test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }
}

// UUID generation
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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

struct UrlData {
    base_url: String,
    parameters: Vec<(String, String)>,
}
