// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

pub mod core;
pub mod loader;
pub mod plugins;
pub mod profiles;
pub mod secrets;
pub mod targets;
pub mod validation;

pub use core::{
    AppConfig, CacheConfig, DatabaseConfig, Environment, FeatureFlags, HttpConfig,
    ObservabilityConfig, RateLimitConfig, RedisConfig, RetryStrategy, ScannerConfig,
    SecretsBackend, SecurityConfig, ServerConfig, SslMode, VaultConfig,
};

pub use loader::{ConfigFormat, ConfigLoader, HotReloadManager, load_config_with_overrides};

pub use plugins::{
    FindingSeverity, Plugin, PluginCapability, PluginConfig, PluginDefinition, PluginFinding,
    PluginInput, PluginManager, PluginMetadata, PluginOutput, PluginType,
};

pub use profiles::{
    ComplianceConfig, ComplianceFramework, PayloadConfig, PayloadSet, ProfileRegistry,
    ProfileSettings, ScanProfile,
};

pub use secrets::{EnvVarsProvider, Secret, SecretsManager, SecretsProvider, VaultProvider};

pub use targets::{
    ApiKeyConfig, AuthConfig, AuthType, Credentials, CustomAuthConfig, ExclusionConfig,
    OAuthConfig, ProxyConfig, ScopeConfig, TargetConfig, TargetRateLimit,
};

pub use validation::{ConfigValidator, ValidationReport};

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

pub struct ConfigManager {
    app_config: Arc<parking_lot::RwLock<AppConfig>>,
    profile_registry: Arc<parking_lot::RwLock<ProfileRegistry>>,
    target_config: Arc<parking_lot::RwLock<TargetConfig>>,
    secrets_manager: Arc<SecretsManager>,
    plugin_manager: Arc<parking_lot::RwLock<PluginManager>>,
}

impl ConfigManager {
    pub async fn new(config_path: &Path) -> Result<Self> {
        let loader = ConfigLoader::new(config_path)?;
        let app_config = loader.load_config()?;

        let secrets_manager = SecretsManager::from_backend(
            app_config.security.secrets_backend,
            app_config.security.vault.clone(),
        )
        .await?;

        let profile_registry = ProfileRegistry::new();
        let target_config = TargetConfig::default();

        let plugin_manager = PluginManager::new(PluginConfig::default());

        Ok(Self {
            app_config: Arc::new(parking_lot::RwLock::new(app_config)),
            profile_registry: Arc::new(parking_lot::RwLock::new(profile_registry)),
            target_config: Arc::new(parking_lot::RwLock::new(target_config)),
            secrets_manager: Arc::new(secrets_manager),
            plugin_manager: Arc::new(parking_lot::RwLock::new(plugin_manager)),
        })
    }

    pub fn get_app_config(&self) -> AppConfig {
        self.app_config.read().clone()
    }

    pub fn update_app_config<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut AppConfig),
    {
        let mut config = self.app_config.write();
        updater(&mut *config);
        ConfigValidator::validate_app_config(&*config)?;
        Ok(())
    }

    pub fn get_profile(&self, name: &str) -> Option<ScanProfile> {
        self.profile_registry.read().get(name).cloned()
    }

    pub fn register_profile(&self, profile: ScanProfile) -> Result<()> {
        ConfigValidator::validate_scan_profile(&profile)?;
        self.profile_registry.write().register(profile);
        Ok(())
    }

    pub fn list_profiles(&self) -> Vec<ScanProfile> {
        self.profile_registry.read().list().iter().map(|p| (*p).clone()).collect()
    }

    pub fn get_target_config(&self) -> TargetConfig {
        self.target_config.read().clone()
    }

    pub fn update_target_config<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut TargetConfig),
    {
        let mut config = self.target_config.write();
        updater(&mut *config);
        ConfigValidator::validate_target_config(&*config)?;
        Ok(())
    }

    pub fn get_secret(&self, key: &str) -> Result<String> {
        self.secrets_manager.get_secret(key)
    }

    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.secrets_manager.set_secret(key, value)
    }

    pub fn get_plugin_manager(&self) -> Arc<parking_lot::RwLock<PluginManager>> {
        Arc::clone(&self.plugin_manager)
    }

    pub fn validate_config(&self) -> ValidationReport {
        let config = self.get_app_config();
        ConfigValidator::generate_validation_report(&config)
    }

    pub async fn reload_from_file(&self, config_path: &Path) -> Result<()> {
        let loader = ConfigLoader::new(config_path)?;
        let new_config = loader.load_config()?;

        ConfigValidator::validate_app_config(&new_config)?;

        {
            let mut config = self.app_config.write();
            *config = new_config;
        }

        tracing::info!("Configuration reloaded successfully from {:?}", config_path);

        Ok(())
    }

    pub fn load_profiles_from_directory(&self, dir_path: &Path) -> Result<()> {
        let loader = ConfigLoader::new(dir_path.join("dummy.yaml"))?;
        let new_registry = loader.load_profiles_from_directory(dir_path)?;

        {
            let mut registry = self.profile_registry.write();
            *registry = new_registry;
        }

        tracing::info!("Profiles loaded from directory: {:?}", dir_path);

        Ok(())
    }

    pub fn load_target_config_from_file(&self, target_path: &Path) -> Result<()> {
        let loader = ConfigLoader::new(target_path)?;
        let new_target_config = loader.load_target_config(target_path)?;

        ConfigValidator::validate_target_config(&new_target_config)?;

        {
            let mut config = self.target_config.write();
            *config = new_target_config;
        }

        tracing::info!("Target configuration loaded from {:?}", target_path);

        Ok(())
    }
}

pub fn create_default_config() -> AppConfig {
    AppConfig {
        server: ServerConfig {
            port: 8080,
            host: "0.0.0.0".to_string(),
            environment: Environment::Development,
            workers: num_cpus::get(),
            graceful_shutdown: true,
            shutdown_timeout_secs: 30,
        },
        redis: RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            pool_size: 20,
            cluster_mode: false,
            connection_timeout_secs: 5,
            max_retries: 3,
            enable_tls: false,
            username: None,
            password: None,
        },
        database: DatabaseConfig {
            enabled: false,
            url: "postgresql://lonkero:lonkero@localhost:5432/lonkero".to_string(),
            pool_size: 20,
            batch_size: 250,
            connection_timeout_secs: 10,
            auto_migrate: true,
            ssl_mode: SslMode::Prefer,
        },
        scanner: ScannerConfig {
            max_concurrency: 100,
            request_timeout_secs: 30,
            max_retries: 2,
            retry_strategy: RetryStrategy::Exponential,
            rate_limiting: RateLimitConfig {
                enabled: true,
                requests_per_second: 100,
                adaptive: true,
                per_target: false,
                burst_size: None,
            },
            http: HttpConfig {
                http2_enabled: true,
                http3_enabled: false,
                http2_adaptive_window: true,
                http2_max_concurrent_streams: 100,
                pool_max_idle_per_host: 20,
                pool_idle_timeout_enabled: true,
                pool_idle_timeout_secs: 90,
                tcp_keepalive: true,
                tcp_nodelay: false,
            },
            cache: CacheConfig {
                enabled: true,
                max_capacity: 10000,
                ttl_secs: 300,
                dns_cache_enabled: true,
                response_cache_enabled: false,
            },
            custom_headers: std::collections::HashMap::new(),
            user_agent: None,
            follow_redirects: true,
            max_redirects: 5,
            subdomain_enum_enabled: false,
            subdomain_enum_thorough: false,
            cdn_detection_enabled: true,
            early_termination_enabled: false,
            // HTTP/2 Configuration (direct fields)
            http2_enabled: true,
            http2_adaptive_window: true,
            http2_max_concurrent_streams: 100,
            pool_max_idle_per_host: 10,
            // Cache Configuration (direct fields)
            cache_enabled: true,
            cache_max_capacity: 10000,
            cache_ttl_secs: 300,
            dns_cache_enabled: true,
            // Rate Limiting Configuration (direct fields)
            rate_limit_enabled: true,
            rate_limit_rps: 100,
            rate_limit_adaptive: true,
            // Request Batching Configuration
            request_batching_enabled: false,
            batch_size: 50,
            // Adaptive Concurrency Configuration
            adaptive_concurrency_enabled: true,
            initial_concurrency: 10,
            max_concurrency_per_target: 50,
        },
        security: SecurityConfig {
            secrets_backend: SecretsBackend::EnvVars,
            vault: None,
            tls_verify: true,
            tls_cert_path: None,
            tls_key_path: None,
            allowed_cipher_suites: Vec::new(),
        },
        features: FeatureFlags::default(),
        observability: ObservabilityConfig::default(),
    }
}

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults
    ///
    /// Supports the following environment variables:
    /// - REDIS_URL: Redis connection URL
    /// - DATABASE_URL: PostgreSQL connection URL (enables database if set)
    /// - MAX_CONCURRENCY: Maximum concurrent requests
    /// - WORKERS: Number of worker threads
    /// - SERVER_PORT: Server port
    /// - LOG_LEVEL: Logging level
    pub fn from_env() -> Result<Self> {
        let mut config = create_default_config();

        // Apply environment variable overrides
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            config.redis.url = redis_url;
        }

        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            config.database.url = db_url;
            config.database.enabled = true;
        }

        if let Ok(concurrency) = std::env::var("MAX_CONCURRENCY") {
            config.scanner.max_concurrency = concurrency
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid MAX_CONCURRENCY value"))?;
        }

        if let Ok(workers) = std::env::var("WORKERS") {
            config.server.workers = workers
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid WORKERS value"))?;
        }

        if let Ok(port) = std::env::var("SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid SERVER_PORT value"))?;
        }

        if let Ok(log_level) = std::env::var("LOG_LEVEL") {
            config.observability.log_level = log_level;
        }

        // Set environment from env var
        if let Ok(env_str) = std::env::var("ENVIRONMENT") {
            config.server.environment = env_str.parse().unwrap_or(Environment::Development);
        }

        Ok(config)
    }
}
