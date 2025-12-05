// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use super::core::{AppConfig, Environment};
use super::profiles::{ProfileRegistry, ScanProfile};
use super::targets::TargetConfig;
use super::validation::ConfigValidator;

pub struct ConfigLoader {
    config_path: PathBuf,
    format: ConfigFormat,
    environment: Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Yaml,
    Toml,
    Json,
}

impl ConfigLoader {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let path = config_path.as_ref().to_path_buf();

        let format = Self::detect_format(&path)?;

        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap_or(Environment::Development);

        Ok(Self {
            config_path: path,
            format,
            environment,
        })
    }

    pub fn with_format<P: AsRef<Path>>(config_path: P, format: ConfigFormat) -> Result<Self> {
        let path = config_path.as_ref().to_path_buf();

        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap_or(Environment::Development);

        Ok(Self {
            config_path: path,
            format,
            environment,
        })
    }

    fn detect_format(path: &Path) -> Result<ConfigFormat> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| anyhow::anyhow!("Could not determine config file format"))?;

        match extension {
            "yaml" | "yml" => Ok(ConfigFormat::Yaml),
            "toml" => Ok(ConfigFormat::Toml),
            "json" => Ok(ConfigFormat::Json),
            _ => Err(anyhow::anyhow!("Unsupported config file format: {}", extension)),
        }
    }

    pub fn load_config(&self) -> Result<AppConfig> {
        let content = std::fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read config file: {:?}", self.config_path))?;

        let mut config: AppConfig = match self.format {
            ConfigFormat::Yaml => serde_yaml::from_str(&content)
                .context("Failed to parse YAML config")?,
            ConfigFormat::Toml => toml::from_str(&content)
                .context("Failed to parse TOML config")?,
            ConfigFormat::Json => serde_json::from_str(&content)
                .context("Failed to parse JSON config")?,
        };

        config.server.environment = self.environment;

        self.apply_env_overrides(&mut config)?;

        ConfigValidator::validate_app_config(&config)?;

        Ok(config)
    }

    fn apply_env_overrides(&self, config: &mut AppConfig) -> Result<()> {
        if let Ok(port) = std::env::var("SERVER_PORT") {
            config.server.port = port.parse()
                .context("Invalid SERVER_PORT")?;
        }

        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            config.redis.url = redis_url;
        }

        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            config.database.url = db_url;
            config.database.enabled = true;
        }

        if let Ok(log_level) = std::env::var("LOG_LEVEL") {
            config.observability.log_level = log_level;
        }

        if let Ok(workers) = std::env::var("WORKERS") {
            config.server.workers = workers.parse()
                .context("Invalid WORKERS")?;
        }

        if let Ok(concurrency) = std::env::var("MAX_CONCURRENCY") {
            config.scanner.max_concurrency = concurrency.parse()
                .context("Invalid MAX_CONCURRENCY")?;
        }

        Ok(())
    }

    pub fn load_profile(&self, profile_path: &Path) -> Result<ScanProfile> {
        let format = Self::detect_format(profile_path)?;
        let content = std::fs::read_to_string(profile_path)
            .with_context(|| format!("Failed to read profile file: {:?}", profile_path))?;

        let profile: ScanProfile = match format {
            ConfigFormat::Yaml => serde_yaml::from_str(&content)?,
            ConfigFormat::Toml => toml::from_str(&content)?,
            ConfigFormat::Json => serde_json::from_str(&content)?,
        };

        ConfigValidator::validate_scan_profile(&profile)?;

        Ok(profile)
    }

    pub fn load_target_config(&self, target_path: &Path) -> Result<TargetConfig> {
        let format = Self::detect_format(target_path)?;
        let content = std::fs::read_to_string(target_path)
            .with_context(|| format!("Failed to read target config file: {:?}", target_path))?;

        let target_config: TargetConfig = match format {
            ConfigFormat::Yaml => serde_yaml::from_str(&content)?,
            ConfigFormat::Toml => toml::from_str(&content)?,
            ConfigFormat::Json => serde_json::from_str(&content)?,
        };

        ConfigValidator::validate_target_config(&target_config)?;

        Ok(target_config)
    }

    pub fn load_profiles_from_directory(&self, dir_path: &Path) -> Result<ProfileRegistry> {
        let mut registry = ProfileRegistry::new();

        if !dir_path.exists() {
            return Ok(registry);
        }

        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Ok(profile) = self.load_profile(&path) {
                    registry.register(profile);
                }
            }
        }

        Ok(registry)
    }

    pub fn save_config(&self, config: &AppConfig) -> Result<()> {
        ConfigValidator::validate_app_config(config)?;

        let content = match self.format {
            ConfigFormat::Yaml => serde_yaml::to_string(config)?,
            ConfigFormat::Toml => toml::to_string_pretty(config)?,
            ConfigFormat::Json => serde_json::to_string_pretty(config)?,
        };

        std::fs::write(&self.config_path, content)
            .with_context(|| format!("Failed to write config file: {:?}", self.config_path))?;

        Ok(())
    }

    pub fn save_profile(&self, profile: &ScanProfile, output_path: &Path) -> Result<()> {
        ConfigValidator::validate_scan_profile(profile)?;

        let format = Self::detect_format(output_path)?;

        let content = match format {
            ConfigFormat::Yaml => serde_yaml::to_string(profile)?,
            ConfigFormat::Toml => toml::to_string_pretty(profile)?,
            ConfigFormat::Json => serde_json::to_string_pretty(profile)?,
        };

        std::fs::write(output_path, content)
            .with_context(|| format!("Failed to write profile file: {:?}", output_path))?;

        Ok(())
    }
}

pub struct HotReloadManager<T: Clone + Send + Sync + DeserializeOwned + 'static> {
    config: Arc<RwLock<T>>,
    config_path: PathBuf,
    reload_tx: broadcast::Sender<T>,
    _watcher: Option<RecommendedWatcher>,
}

impl<T: Clone + Send + Sync + DeserializeOwned + 'static> HotReloadManager<T> {
    pub fn new(initial_config: T, config_path: PathBuf) -> Result<Self> {
        let config = Arc::new(RwLock::new(initial_config));
        let (reload_tx, _) = broadcast::channel(100);

        Ok(Self {
            config,
            config_path,
            reload_tx,
            _watcher: None,
        })
    }

    pub fn start_watching(mut self) -> Result<Self> {
        let config = Arc::clone(&self.config);
        let reload_tx = self.reload_tx.clone();
        let config_path = self.config_path.clone();

        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })?;

        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;

        tokio::spawn(async move {
            let mut debounce_timer: Option<tokio::time::Instant> = None;

            while let Some(event) = rx.recv().await {
                use notify::EventKind;

                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        let now = tokio::time::Instant::now();

                        if let Some(last_reload) = debounce_timer {
                            if now.duration_since(last_reload) < Duration::from_millis(500) {
                                continue;
                            }
                        }

                        debounce_timer = Some(now);

                        if let Err(e) = Self::reload_config_internal(
                            &config,
                            &config_path,
                            &reload_tx,
                        ).await {
                            tracing::error!("Failed to reload config: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        });

        self._watcher = Some(watcher);
        Ok(self)
    }

    async fn reload_config_internal(
        config: &Arc<RwLock<T>>,
        config_path: &Path,
        reload_tx: &broadcast::Sender<T>,
    ) -> Result<()> {
        let content = tokio::fs::read_to_string(config_path).await?;

        let new_config: T = if config_path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || config_path.extension().and_then(|e| e.to_str()) == Some("yml") {
            serde_yaml::from_str(&content)?
        } else if config_path.extension().and_then(|e| e.to_str()) == Some("toml") {
            toml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };

        {
            let mut config_write = config.write();
            *config_write = new_config.clone();
        }

        let _ = reload_tx.send(new_config);

        tracing::info!("Configuration reloaded successfully");

        Ok(())
    }

    pub fn get_config(&self) -> T {
        self.config.read().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.reload_tx.subscribe()
    }

    pub fn update_config<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut T),
    {
        let mut config = self.config.write();
        updater(&mut *config);
        let _ = self.reload_tx.send(config.clone());
        Ok(())
    }
}

trait EnvironmentParse {
    fn parse(s: &str) -> Result<Self>
    where
        Self: Sized;
}

impl EnvironmentParse for Environment {
    fn parse(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "staging" | "stage" => Ok(Environment::Staging),
            "production" | "prod" => Ok(Environment::Production),
            _ => Err(anyhow::anyhow!("Invalid environment: {}", s)),
        }
    }
}

pub fn load_config_with_overrides(base_path: &str, environment: Environment) -> Result<AppConfig> {
    let base_config_path = PathBuf::from(base_path);

    let mut builder = config::Config::builder()
        .add_source(config::File::from(base_config_path));

    let env_config_path = match environment {
        Environment::Development => "config/development.yaml",
        Environment::Staging => "config/staging.yaml",
        Environment::Production => "config/production.yaml",
    };

    let env_path = PathBuf::from(env_config_path);
    if env_path.exists() {
        builder = builder.add_source(config::File::from(env_path));
    }

    builder = builder.add_source(
        config::Environment::with_prefix("APP")
            .separator("__")
            .try_parsing(true)
    );

    let settings = builder.build()?;
    let app_config: AppConfig = settings.try_deserialize()?;

    ConfigValidator::validate_app_config(&app_config)?;

    Ok(app_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_detect_format() {
        assert_eq!(
            ConfigLoader::detect_format(Path::new("config.yaml")).unwrap(),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigLoader::detect_format(Path::new("config.toml")).unwrap(),
            ConfigFormat::Toml
        );
        assert_eq!(
            ConfigLoader::detect_format(Path::new("config.json")).unwrap(),
            ConfigFormat::Json
        );
    }

    #[test]
    fn test_load_yaml_config() -> Result<()> {
        let yaml_content = r#"
server:
  port: 8080
  host: "0.0.0.0"
  workers: 4
redis:
  url: "redis://localhost:6379"
  pool_size: 20
database:
  enabled: false
  url: "postgresql://localhost/test"
  pool_size: 20
  batch_size: 100
scanner:
  max_concurrency: 100
  request_timeout_secs: 30
  max_retries: 2
security:
  secrets_backend: "env-vars"
  tls_verify: true
"#;

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(yaml_content.as_bytes())?;
        temp_file.flush()?;

        let loader = ConfigLoader::with_format(temp_file.path(), ConfigFormat::Yaml)?;
        let config = loader.load_config()?;

        assert_eq!(config.server.port, 8080);
        assert_eq!(config.redis.url, "redis://localhost:6379");

        Ok(())
    }
}
