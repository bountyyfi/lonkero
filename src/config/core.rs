// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AppConfig {
    pub server: ServerConfig,

    pub redis: RedisConfig,

    pub database: DatabaseConfig,

    pub scanner: ScannerConfig,

    pub security: SecurityConfig,

    #[serde(default)]
    pub features: FeatureFlags,

    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerConfig {
    #[validate(range(min = 1024, max = 65535))]
    pub port: u16,

    #[validate(length(min = 1))]
    pub host: String,

    #[serde(default = "default_environment")]
    pub environment: Environment,

    #[validate(range(min = 1))]
    #[serde(default = "default_workers")]
    pub workers: usize,

    #[serde(default = "default_true")]
    pub graceful_shutdown: bool,

    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RedisConfig {
    #[validate(url)]
    pub url: String,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: usize,

    #[serde(default = "default_true")]
    pub cluster_mode: bool,

    #[serde(default)]
    pub connection_timeout_secs: u64,

    #[serde(default = "default_redis_retry")]
    pub max_retries: u32,

    #[serde(default)]
    pub enable_tls: bool,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DatabaseConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,

    #[validate(url)]
    #[serde(default = "default_database_url")]
    pub url: String,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_db_pool_size")]
    pub pool_size: usize,

    #[validate(range(min = 1))]
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    #[serde(default = "default_true")]
    pub auto_migrate: bool,

    #[serde(default)]
    pub ssl_mode: SslMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ScannerConfig {
    #[validate(range(min = 1, max = 10000))]
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,

    #[validate(range(min = 1, max = 3600))]
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,

    #[validate(range(min = 0, max = 10))]
    #[serde(default = "default_retries")]
    pub max_retries: u32,

    #[serde(default)]
    pub retry_strategy: RetryStrategy,

    #[serde(default)]
    pub rate_limiting: RateLimitConfig,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub custom_headers: HashMap<String, String>,

    #[serde(default)]
    pub user_agent: Option<String>,

    #[serde(default = "default_true")]
    pub follow_redirects: bool,

    #[validate(range(min = 0, max = 20))]
    #[serde(default = "default_redirect_limit")]
    pub max_redirects: usize,

    #[serde(default)]
    pub subdomain_enum_enabled: bool,

    #[serde(default)]
    pub subdomain_enum_thorough: bool,

    #[serde(default = "default_true")]
    pub cdn_detection_enabled: bool,

    #[serde(default)]
    pub early_termination_enabled: bool,

    // HTTP/2 Configuration
    #[serde(default = "default_true")]
    pub http2_enabled: bool,

    #[serde(default = "default_true")]
    pub http2_adaptive_window: bool,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_concurrent_streams")]
    pub http2_max_concurrent_streams: usize,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_pool_idle_per_host")]
    pub pool_max_idle_per_host: usize,

    // Cache Configuration
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    #[validate(range(min = 1, max = 1000000))]
    #[serde(default = "default_cache_capacity_usize")]
    pub cache_max_capacity: usize,

    #[validate(range(min = 1, max = 86400))]
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    #[serde(default = "default_true")]
    pub dns_cache_enabled: bool,

    // Rate Limiting Configuration
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,

    #[validate(range(min = 1, max = 100000))]
    #[serde(default = "default_rps")]
    pub rate_limit_rps: u32,

    #[serde(default = "default_true")]
    pub rate_limit_adaptive: bool,

    // Request Batching Configuration
    #[serde(default = "default_false")]
    pub request_batching_enabled: bool,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_batch_size_50")]
    pub batch_size: usize,

    // Adaptive Concurrency Configuration
    #[serde(default = "default_true")]
    pub adaptive_concurrency_enabled: bool,

    #[validate(range(min = 1, max = 100))]
    #[serde(default = "default_initial_concurrency")]
    pub initial_concurrency: usize,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_max_concurrency_per_target")]
    pub max_concurrency_per_target: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[validate(range(min = 1, max = 100000))]
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,

    #[serde(default = "default_true")]
    pub adaptive: bool,

    #[serde(default)]
    pub per_target: bool,

    #[serde(default)]
    pub burst_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct HttpConfig {
    #[serde(default = "default_true")]
    pub http2_enabled: bool,

    #[serde(default = "default_false")]
    pub http3_enabled: bool,

    #[serde(default = "default_true")]
    pub http2_adaptive_window: bool,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_concurrent_streams")]
    pub http2_max_concurrent_streams: usize,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_pool_idle")]
    pub pool_max_idle_per_host: usize,

    #[serde(default = "default_true")]
    pub pool_idle_timeout_enabled: bool,

    #[serde(default)]
    pub pool_idle_timeout_secs: u64,

    #[serde(default = "default_true")]
    pub tcp_keepalive: bool,

    #[serde(default)]
    pub tcp_nodelay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[validate(range(min = 1, max = 1000000))]
    #[serde(default = "default_cache_capacity")]
    pub max_capacity: u64,

    #[validate(range(min = 1, max = 86400))]
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,

    #[serde(default = "default_true")]
    pub dns_cache_enabled: bool,

    #[serde(default)]
    pub response_cache_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub secrets_backend: SecretsBackend,

    #[serde(default)]
    pub vault: Option<VaultConfig>,

    #[serde(default = "default_true")]
    pub tls_verify: bool,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default)]
    pub allowed_cipher_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub mount_path: String,
    #[serde(default = "default_false")]
    pub use_app_role: bool,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub secret_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    #[serde(default = "default_false")]
    pub early_termination_enabled: bool,

    #[serde(default = "default_true")]
    pub cdn_detection_enabled: bool,

    #[serde(default = "default_true")]
    pub payload_prioritization_enabled: bool,

    #[serde(default = "default_true")]
    pub request_batching_enabled: bool,

    #[serde(default = "default_true")]
    pub adaptive_concurrency_enabled: bool,

    #[serde(default = "default_false")]
    pub machine_learning_enabled: bool,

    #[serde(default = "default_true")]
    pub framework_detection_enabled: bool,

    #[serde(default = "default_false")]
    pub crawler_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    #[serde(default = "default_true")]
    pub tracing_enabled: bool,

    #[serde(default)]
    pub tracing_endpoint: Option<String>,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_false")]
    pub log_json: bool,

    #[serde(default = "default_true")]
    pub health_check_enabled: bool,

    #[serde(default = "default_health_port")]
    pub health_check_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretsBackend {
    EnvVars,
    Vault,
    AwsSecretsManager,
    GcpSecretManager,
    AzureKeyVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetryStrategy {
    Exponential,
    Linear,
    Fixed,
}

impl Default for Environment {
    fn default() -> Self {
        Self::Development
    }
}

impl std::str::FromStr for Environment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "staging" | "stage" => Ok(Environment::Staging),
            "production" | "prod" => Ok(Environment::Production),
            _ => Err(anyhow::anyhow!("Invalid environment: {}", s)),
        }
    }
}

impl Default for SecretsBackend {
    fn default() -> Self {
        Self::EnvVars
    }
}

impl Default for SslMode {
    fn default() -> Self {
        Self::Prefer
    }
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::Exponential
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            early_termination_enabled: false,
            cdn_detection_enabled: true,
            payload_prioritization_enabled: true,
            request_batching_enabled: true,
            adaptive_concurrency_enabled: true,
            machine_learning_enabled: false,
            framework_detection_enabled: true,
            crawler_enabled: false,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            tracing_enabled: true,
            tracing_endpoint: None,
            log_level: "info".to_string(),
            log_json: false,
            health_check_enabled: true,
            health_check_port: 8080,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            adaptive: true,
            per_target: false,
            burst_size: None,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            http2_enabled: true,
            http3_enabled: false,
            http2_adaptive_window: true,
            http2_max_concurrent_streams: 100,
            pool_max_idle_per_host: 20,
            pool_idle_timeout_enabled: true,
            pool_idle_timeout_secs: 90,
            tcp_keepalive: true,
            tcp_nodelay: false,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_capacity: 10000,
            ttl_secs: 300,
            dns_cache_enabled: true,
            response_cache_enabled: false,
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 50,
            request_timeout_secs: 30,
            max_retries: 2,
            retry_strategy: Default::default(),
            rate_limiting: Default::default(),
            http: Default::default(),
            cache: Default::default(),
            custom_headers: Default::default(),
            user_agent: None,
            follow_redirects: true,
            max_redirects: 5,
            subdomain_enum_enabled: false,
            subdomain_enum_thorough: false,
            cdn_detection_enabled: true,
            early_termination_enabled: false,
            http2_enabled: true,
            http2_adaptive_window: true,
            http2_max_concurrent_streams: 100,
            pool_max_idle_per_host: 10,
            cache_enabled: true,
            cache_max_capacity: 10000,
            cache_ttl_secs: 300,
            dns_cache_enabled: true,
            rate_limit_enabled: true,
            rate_limit_rps: 100,
            rate_limit_adaptive: true,
            request_batching_enabled: false,
            batch_size: 50,
            adaptive_concurrency_enabled: true,
            initial_concurrency: 10,
            max_concurrency_per_target: 50,
        }
    }
}

impl RetryStrategy {
    pub fn calculate_delay(&self, attempt: u32, base_delay_ms: u64) -> Duration {
        let delay_ms = match self {
            Self::Exponential => base_delay_ms * 2_u64.pow(attempt),
            Self::Linear => base_delay_ms * (attempt as u64 + 1),
            Self::Fixed => base_delay_ms,
        };
        Duration::from_millis(delay_ms.min(60000))
    }
}

fn default_environment() -> Environment {
    Environment::Development
}

fn default_workers() -> usize {
    num_cpus::get()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_redis_pool_size() -> usize {
    20
}

fn default_redis_retry() -> u32 {
    3
}

fn default_database_url() -> String {
    "postgresql://lonkero:lonkero@localhost:5432/lonkero".to_string()
}

fn default_db_pool_size() -> usize {
    20
}

fn default_batch_size() -> usize {
    250
}

fn default_connection_timeout() -> u64 {
    10
}

fn default_concurrency() -> usize {
    100
}

fn default_timeout() -> u64 {
    30
}

fn default_retries() -> u32 {
    2
}

fn default_redirect_limit() -> usize {
    5
}

fn default_rps() -> u32 {
    100
}

fn default_concurrent_streams() -> usize {
    100
}

fn default_pool_idle() -> usize {
    20
}

fn default_cache_capacity() -> u64 {
    10000
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_health_port() -> u16 {
    8080
}

fn default_pool_idle_per_host() -> usize {
    10
}

fn default_cache_capacity_usize() -> usize {
    10000
}

fn default_batch_size_50() -> usize {
    50
}

fn default_initial_concurrency() -> usize {
    10
}

fn default_max_concurrency_per_target() -> usize {
    50
}
