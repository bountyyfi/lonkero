// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PluginConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_plugin_dir")]
    pub plugin_directory: PathBuf,

    #[serde(default)]
    pub auto_discover: bool,

    #[serde(default)]
    pub plugins: HashMap<String, PluginDefinition>,

    #[validate(range(min = 1, max = 300))]
    #[serde(default = "default_plugin_timeout")]
    pub plugin_timeout_secs: u64,

    #[serde(default = "default_true")]
    pub sandbox_enabled: bool,

    #[serde(default)]
    pub allowed_capabilities: Vec<PluginCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PluginDefinition {
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub description: Option<String>,

    pub plugin_type: PluginType,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub path: Option<PathBuf>,

    #[serde(default)]
    pub entry_point: Option<String>,

    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,

    #[serde(default)]
    pub dependencies: Vec<String>,

    #[serde(default)]
    pub priority: i32,

    #[serde(default)]
    pub required_capabilities: Vec<PluginCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginType {
    Scanner,
    PayloadGenerator,
    ResponseAnalyzer,
    Preprocessor,
    Postprocessor,
    Reporter,
    Integration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginCapability {
    NetworkAccess,
    FileSystemRead,
    FileSystemWrite,
    DatabaseAccess,
    ExternalProcess,
    EnvironmentAccess,
    ConfigModification,
}

#[derive(Debug)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub plugin_type: PluginType,
    pub required_capabilities: Vec<PluginCapability>,
    pub schema_version: String,
}

pub trait Plugin: Send + Sync {
    fn metadata(&self) -> &PluginMetadata;

    fn initialize(&mut self, config: &HashMap<String, serde_json::Value>) -> anyhow::Result<()>;

    fn execute(&self, input: PluginInput) -> anyhow::Result<PluginOutput>;

    fn shutdown(&mut self) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub findings: Vec<PluginFinding>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub recommendation: Option<String>,
    pub cwe: Option<u32>,
    pub cvss_score: Option<f32>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct PluginManager {
    plugins: HashMap<String, Box<dyn Plugin>>,
    config: PluginConfig,
}

impl PluginManager {
    pub fn new(config: PluginConfig) -> Self {
        Self {
            plugins: HashMap::new(),
            config,
        }
    }

    pub fn register_plugin(&mut self, plugin: Box<dyn Plugin>) -> anyhow::Result<()> {
        let metadata = plugin.metadata();

        if self.config.sandbox_enabled {
            self.validate_capabilities(&metadata.required_capabilities)?;
        }

        self.plugins.insert(metadata.name.clone(), plugin);
        Ok(())
    }

    pub fn load_plugins(&mut self) -> anyhow::Result<()> {
        if !self.config.auto_discover {
            return Ok(());
        }

        if !self.config.plugin_directory.exists() {
            return Ok(());
        }

        Ok(())
    }

    pub fn execute_plugin(
        &self,
        plugin_name: &str,
        input: PluginInput,
    ) -> anyhow::Result<PluginOutput> {
        let plugin = self.plugins.get(plugin_name)
            .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", plugin_name))?;

        plugin.execute(input)
    }

    pub fn list_plugins(&self) -> Vec<&PluginMetadata> {
        self.plugins.values()
            .map(|p| p.metadata())
            .collect()
    }

    pub fn get_plugin(&self, name: &str) -> Option<&Box<dyn Plugin>> {
        self.plugins.get(name)
    }

    fn validate_capabilities(&self, required: &[PluginCapability]) -> anyhow::Result<()> {
        for capability in required {
            if !self.config.allowed_capabilities.contains(capability) {
                return Err(anyhow::anyhow!(
                    "Plugin requires capability {:?} which is not allowed",
                    capability
                ));
            }
        }
        Ok(())
    }

    pub fn shutdown_all(&mut self) -> anyhow::Result<()> {
        for plugin in self.plugins.values_mut() {
            let plugin_name = plugin.metadata().name.clone();
            if let Err(e) = plugin.shutdown() {
                tracing::error!("Failed to shutdown plugin '{}': {}", plugin_name, e);
            }
        }
        Ok(())
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            plugin_directory: default_plugin_dir(),
            auto_discover: false,
            plugins: HashMap::new(),
            plugin_timeout_secs: 60,
            sandbox_enabled: true,
            allowed_capabilities: vec![
                PluginCapability::NetworkAccess,
                PluginCapability::FileSystemRead,
            ],
        }
    }
}

impl PluginDefinition {
    pub fn new(name: String, plugin_type: PluginType) -> Self {
        Self {
            name,
            version: None,
            description: None,
            plugin_type,
            enabled: true,
            path: None,
            entry_point: None,
            config: HashMap::new(),
            dependencies: Vec::new(),
            priority: 0,
            required_capabilities: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_plugin_dir() -> PathBuf {
    PathBuf::from("./plugins")
}

fn default_plugin_timeout() -> u64 {
    60
}
