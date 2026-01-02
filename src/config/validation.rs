// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::{Context, Result};
use std::collections::HashMap;
use validator::Validate;

use super::core::AppConfig;
use super::profiles::ScanProfile;
use super::targets::TargetConfig;

pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate_app_config(config: &AppConfig) -> Result<()> {
        config.validate()
            .context("Configuration validation failed")?;

        Self::validate_redis_config(config)?;
        Self::validate_database_config(config)?;
        Self::validate_scanner_config(config)?;
        Self::validate_security_config(config)?;

        Ok(())
    }

    fn validate_redis_config(config: &AppConfig) -> Result<()> {
        if config.redis.url.is_empty() {
            return Err(anyhow::anyhow!("Redis URL cannot be empty"));
        }

        if !config.redis.url.starts_with("redis://") && !config.redis.url.starts_with("rediss://") {
            return Err(anyhow::anyhow!(
                "Redis URL must start with redis:// or rediss://"
            ));
        }

        if config.redis.pool_size == 0 {
            return Err(anyhow::anyhow!("Redis pool size must be greater than 0"));
        }

        Ok(())
    }

    fn validate_database_config(config: &AppConfig) -> Result<()> {
        if !config.database.enabled {
            return Ok(());
        }

        if config.database.url.is_empty() {
            return Err(anyhow::anyhow!("Database URL cannot be empty when database is enabled"));
        }

        if !config.database.url.starts_with("postgresql://")
            && !config.database.url.starts_with("postgres://") {
            return Err(anyhow::anyhow!(
                "Database URL must start with postgresql:// or postgres://"
            ));
        }

        if config.database.pool_size == 0 {
            return Err(anyhow::anyhow!("Database pool size must be greater than 0"));
        }

        if config.database.batch_size == 0 {
            return Err(anyhow::anyhow!("Database batch size must be greater than 0"));
        }

        Ok(())
    }

    fn validate_scanner_config(config: &AppConfig) -> Result<()> {
        if config.scanner.max_concurrency == 0 {
            return Err(anyhow::anyhow!("Max concurrency must be greater than 0"));
        }

        if config.scanner.request_timeout_secs == 0 {
            return Err(anyhow::anyhow!("Request timeout must be greater than 0"));
        }

        if config.scanner.rate_limiting.enabled {
            if config.scanner.rate_limiting.requests_per_second == 0 {
                return Err(anyhow::anyhow!(
                    "Rate limit requests per second must be greater than 0 when enabled"
                ));
            }
        }

        if config.scanner.cache.enabled {
            if config.scanner.cache.max_capacity == 0 {
                return Err(anyhow::anyhow!("Cache capacity must be greater than 0 when enabled"));
            }

            if config.scanner.cache.ttl_secs == 0 {
                return Err(anyhow::anyhow!("Cache TTL must be greater than 0 when enabled"));
            }
        }

        Ok(())
    }

    fn validate_security_config(config: &AppConfig) -> Result<()> {
        use super::core::SecretsBackend;

        match config.security.secrets_backend {
            SecretsBackend::Vault => {
                let vault = config.security.vault.as_ref()
                    .ok_or_else(|| anyhow::anyhow!(
                        "Vault configuration required when using Vault secrets backend"
                    ))?;

                if vault.address.is_empty() {
                    return Err(anyhow::anyhow!("Vault address cannot be empty"));
                }

                if vault.use_app_role {
                    if vault.role_id.is_none() || vault.secret_id.is_none() {
                        return Err(anyhow::anyhow!(
                            "Both role_id and secret_id required for AppRole authentication"
                        ));
                    }
                } else if vault.token.is_empty() {
                    return Err(anyhow::anyhow!("Vault token cannot be empty"));
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn validate_scan_profile(profile: &ScanProfile) -> Result<()> {
        profile.validate()
            .context("Scan profile validation failed")?;

        if profile.name.is_empty() {
            return Err(anyhow::anyhow!("Profile name cannot be empty"));
        }

        if profile.settings.max_concurrency == 0 {
            return Err(anyhow::anyhow!("Profile max concurrency must be greater than 0"));
        }

        if profile.settings.request_timeout_secs == 0 {
            return Err(anyhow::anyhow!("Profile request timeout must be greater than 0"));
        }

        if profile.settings.max_requests_per_second == 0 {
            return Err(anyhow::anyhow!("Profile max RPS must be greater than 0"));
        }

        if !profile.enabled_scanners.is_empty() && !profile.disabled_scanners.is_empty() {
            let intersection: Vec<_> = profile.enabled_scanners
                .intersection(&profile.disabled_scanners)
                .collect();

            if !intersection.is_empty() {
                return Err(anyhow::anyhow!(
                    "Scanners cannot be both enabled and disabled: {:?}",
                    intersection
                ));
            }
        }

        Ok(())
    }

    pub fn validate_target_config(target: &TargetConfig) -> Result<()> {
        target.validate()
            .context("Target configuration validation failed")?;

        if !target.scope.included_domains.is_empty() {
            for domain in &target.scope.included_domains {
                if domain.is_empty() {
                    return Err(anyhow::anyhow!("Domain in included_domains cannot be empty"));
                }
            }
        }

        for pattern in &target.scope.included_patterns {
            regex::Regex::new(pattern)
                .with_context(|| format!("Invalid regex pattern in included_patterns: {}", pattern))?;
        }

        for pattern in &target.scope.excluded_patterns {
            regex::Regex::new(pattern)
                .with_context(|| format!("Invalid regex pattern in excluded_patterns: {}", pattern))?;
        }

        for pattern in &target.exclusions.path_patterns {
            regex::Regex::new(pattern)
                .with_context(|| format!("Invalid regex pattern in path_patterns: {}", pattern))?;
        }

        if let Some(proxy) = &target.proxy {
            proxy.validate()
                .context("Proxy configuration validation failed")?;
        }

        Ok(())
    }

    pub fn generate_validation_report(config: &AppConfig) -> ValidationReport {
        let mut report = ValidationReport::new();

        if let Err(e) = Self::validate_app_config(config) {
            report.add_error("app_config", &e.to_string());
        }

        if config.scanner.max_concurrency > 1000 {
            report.add_warning(
                "scanner.max_concurrency",
                "Very high concurrency may cause resource exhaustion"
            );
        }

        if config.scanner.request_timeout_secs > 300 {
            report.add_warning(
                "scanner.request_timeout_secs",
                "Very high timeout may cause slow scans"
            );
        }

        if config.scanner.rate_limiting.enabled && config.scanner.rate_limiting.requests_per_second > 1000 {
            report.add_warning(
                "scanner.rate_limiting.requests_per_second",
                "Very high rate limit may overwhelm target servers"
            );
        }

        if !config.scanner.cache.enabled {
            report.add_info(
                "scanner.cache.enabled",
                "Response caching is disabled, scans may be slower"
            );
        }

        if config.database.enabled && config.database.pool_size < 10 {
            report.add_warning(
                "database.pool_size",
                "Low database pool size may cause connection bottlenecks"
            );
        }

        if config.features.early_termination_enabled {
            report.add_info(
                "features.early_termination_enabled",
                "Early termination may miss some vulnerabilities"
            );
        }

        report
    }
}

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub errors: HashMap<String, Vec<String>>,
    pub warnings: HashMap<String, Vec<String>>,
    pub info: HashMap<String, Vec<String>>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            errors: HashMap::new(),
            warnings: HashMap::new(),
            info: HashMap::new(),
        }
    }

    pub fn add_error(&mut self, field: &str, message: &str) {
        self.errors
            .entry(field.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_string());
    }

    pub fn add_warning(&mut self, field: &str, message: &str) {
        self.warnings
            .entry(field.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_string());
    }

    pub fn add_info(&mut self, field: &str, message: &str) {
        self.info
            .entry(field.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_string());
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn print_report(&self) {
        if !self.errors.is_empty() {
            println!("\n[ERROR] Errors:");
            for (field, messages) in &self.errors {
                for message in messages {
                    println!("  - {}: {}", field, message);
                }
            }
        }

        if !self.warnings.is_empty() {
            println!("\n[WARNING]  Warnings:");
            for (field, messages) in &self.warnings {
                for message in messages {
                    println!("  - {}: {}", field, message);
                }
            }
        }

        if !self.info.is_empty() {
            println!("\n[INFO]  Info:");
            for (field, messages) in &self.info {
                for message in messages {
                    println!("  - {}: {}", field, message);
                }
            }
        }

        if self.errors.is_empty() && self.warnings.is_empty() && self.info.is_empty() {
            println!("\n[SUCCESS] Configuration validation passed!");
        }
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::core::*;

    fn create_valid_config() -> AppConfig {
        AppConfig {
            server: ServerConfig {
                port: 8080,
                host: "0.0.0.0".to_string(),
                environment: Environment::Development,
                workers: 4,
                graceful_shutdown: true,
                shutdown_timeout_secs: 30,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
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
                url: "postgresql://localhost/test".to_string(),
                pool_size: 20,
                batch_size: 100,
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
                custom_headers: HashMap::new(),
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
                pool_max_idle_per_host: 20,
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

    #[test]
    fn test_valid_config() {
        let config = create_valid_config();
        assert!(ConfigValidator::validate_app_config(&config).is_ok());
    }

    #[test]
    fn test_invalid_redis_url() {
        let mut config = create_valid_config();
        config.redis.url = "invalid://url".to_string();
        assert!(ConfigValidator::validate_app_config(&config).is_err());
    }

    #[test]
    fn test_validation_report() {
        let config = create_valid_config();
        let report = ConfigValidator::generate_validation_report(&config);
        assert!(!report.has_errors());
    }
}
