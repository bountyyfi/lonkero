// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

use super::core::{SecretsBackend, VaultConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub trait SecretsProvider: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<String>;
    fn set_secret(&self, key: &str, value: &str) -> Result<()>;
    fn delete_secret(&self, key: &str) -> Result<()>;
    fn list_secrets(&self) -> Result<Vec<String>>;
}

pub struct EnvVarsProvider;

impl SecretsProvider for EnvVarsProvider {
    fn get_secret(&self, key: &str) -> Result<String> {
        env::var(key).with_context(|| format!("Environment variable '{}' not found", key))
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        env::set_var(key, value);
        Ok(())
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        env::remove_var(key);
        Ok(())
    }

    fn list_secrets(&self) -> Result<Vec<String>> {
        Ok(env::vars().map(|(k, _)| k).collect())
    }
}

pub struct VaultProvider {
    config: VaultConfig,
    client: VaultClient,
}

impl VaultProvider {
    pub async fn new(config: VaultConfig) -> Result<Self> {
        let client = VaultClient::new(config.clone()).await?;
        Ok(Self { config, client })
    }
}

impl SecretsProvider for VaultProvider {
    fn get_secret(&self, key: &str) -> Result<String> {
        let path = format!("{}/{}", self.config.mount_path, key);
        self.client.read_secret(&path)
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let path = format!("{}/{}", self.config.mount_path, key);
        self.client.write_secret(&path, value)
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        let path = format!("{}/{}", self.config.mount_path, key);
        self.client.delete_secret(&path)
    }

    fn list_secrets(&self) -> Result<Vec<String>> {
        let path = &self.config.mount_path;
        self.client.list_secrets(path)
    }
}

struct VaultClient {
    address: String,
    token: String,
    client: reqwest::Client,
}

impl VaultClient {
    async fn new(config: VaultConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let token = if config.use_app_role {
            Self::authenticate_app_role(
                &client,
                &config.address,
                config.role_id.as_deref().unwrap_or(""),
                config.secret_id.as_deref().unwrap_or(""),
            )
            .await?
        } else {
            config.token.clone()
        };

        Ok(Self {
            address: config.address.clone(),
            token,
            client,
        })
    }

    async fn authenticate_app_role(
        client: &reqwest::Client,
        address: &str,
        role_id: &str,
        secret_id: &str,
    ) -> Result<String> {
        let url = format!("{}/v1/auth/approle/login", address);
        let payload = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        let response = client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;

        let token = response["auth"]["client_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to extract token from Vault response"))?
            .to_string();

        Ok(token)
    }

    fn read_secret(&self, path: &str) -> Result<String> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let url = format!("{}/v1/{}", self.address, path);
            let response = self
                .client
                .get(&url)
                .header("X-Vault-Token", &self.token)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?;

            let secret = response["data"]["value"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Secret value not found in response"))?
                .to_string();

            Ok(secret)
        })
    }

    fn write_secret(&self, path: &str, value: &str) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let url = format!("{}/v1/{}", self.address, path);
            let payload = serde_json::json!({
                "value": value
            });

            self.client
                .post(&url)
                .header("X-Vault-Token", &self.token)
                .json(&payload)
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }

    fn delete_secret(&self, path: &str) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let url = format!("{}/v1/{}", self.address, path);

            self.client
                .delete(&url)
                .header("X-Vault-Token", &self.token)
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }

    fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let url = format!("{}/v1/{}?list=true", self.address, path);
            let response = self
                .client
                .get(&url)
                .header("X-Vault-Token", &self.token)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?;

            let keys = response["data"]["keys"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Keys not found in response"))?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();

            Ok(keys)
        })
    }
}

pub struct SecretsManager {
    provider: Box<dyn SecretsProvider>,
    cache: parking_lot::RwLock<HashMap<String, String>>,
}

impl SecretsManager {
    pub fn new(provider: Box<dyn SecretsProvider>) -> Self {
        Self {
            provider,
            cache: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub async fn from_backend(
        backend: SecretsBackend,
        vault_config: Option<VaultConfig>,
    ) -> Result<Self> {
        let provider: Box<dyn SecretsProvider> = match backend {
            SecretsBackend::EnvVars => Box::new(EnvVarsProvider),
            SecretsBackend::Vault => {
                let config = vault_config
                    .ok_or_else(|| anyhow::anyhow!("Vault config required for Vault backend"))?;
                Box::new(VaultProvider::new(config).await?)
            }
            SecretsBackend::AwsSecretsManager => {
                return Err(anyhow::anyhow!("AWS Secrets Manager not yet implemented"));
            }
            SecretsBackend::GcpSecretManager => {
                return Err(anyhow::anyhow!("GCP Secret Manager not yet implemented"));
            }
            SecretsBackend::AzureKeyVault => {
                return Err(anyhow::anyhow!("Azure Key Vault not yet implemented"));
            }
        };

        Ok(Self::new(provider))
    }

    pub fn get_secret(&self, key: &str) -> Result<String> {
        {
            let cache = self.cache.read();
            if let Some(value) = cache.get(key) {
                return Ok(value.clone());
            }
        }

        let value = self.provider.get_secret(key)?;

        {
            let mut cache = self.cache.write();
            cache.insert(key.to_string(), value.clone());
        }

        Ok(value)
    }

    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.provider.set_secret(key, value)?;

        {
            let mut cache = self.cache.write();
            cache.insert(key.to_string(), value.to_string());
        }

        Ok(())
    }

    pub fn delete_secret(&self, key: &str) -> Result<()> {
        self.provider.delete_secret(key)?;

        {
            let mut cache = self.cache.write();
            cache.remove(key);
        }

        Ok(())
    }

    pub fn list_secrets(&self) -> Result<Vec<String>> {
        self.provider.list_secrets()
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }

    pub fn resolve_template(&self, template: &str) -> Result<String> {
        let re = regex::Regex::new(r"\$\{([^}]+)\}")
            .context("Failed to compile template regex pattern")?;
        let mut result = template.to_string();

        for cap in re.captures_iter(template) {
            if let Some(key) = cap.get(1) {
                let secret_value = self.get_secret(key.as_str())?;
                result = result.replace(&format!("${{{}}}", key.as_str()), &secret_value);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_vars_provider() {
        let provider = EnvVarsProvider;

        env::set_var("TEST_SECRET", "test_value");

        let result = provider.get_secret("TEST_SECRET").unwrap();
        assert_eq!(result, "test_value");

        provider.delete_secret("TEST_SECRET").unwrap();
        assert!(provider.get_secret("TEST_SECRET").is_err());
    }

    #[test]
    fn test_secrets_manager_cache() {
        let provider = Box::new(EnvVarsProvider);
        let manager = SecretsManager::new(provider);

        env::set_var("CACHE_TEST", "cached_value");

        let result1 = manager.get_secret("CACHE_TEST").unwrap();
        assert_eq!(result1, "cached_value");

        env::set_var("CACHE_TEST", "new_value");

        let result2 = manager.get_secret("CACHE_TEST").unwrap();
        assert_eq!(result2, "cached_value");

        manager.clear_cache();

        let result3 = manager.get_secret("CACHE_TEST").unwrap();
        assert_eq!(result3, "new_value");

        env::remove_var("CACHE_TEST");
    }

    #[test]
    fn test_template_resolution() {
        let provider = Box::new(EnvVarsProvider);
        let manager = SecretsManager::new(provider);

        env::set_var("DB_USER", "admin");
        env::set_var("DB_PASS", "secret123");

        let template = "postgresql://${DB_USER}:${DB_PASS}@localhost/db";
        let resolved = manager.resolve_template(template).unwrap();
        assert_eq!(resolved, "postgresql://admin:secret123@localhost/db");

        env::remove_var("DB_USER");
        env::remove_var("DB_PASS");
    }
}
