// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TargetConfig {
    #[serde(default)]
    pub scope: ScopeConfig,

    #[serde(default)]
    pub exclusions: ExclusionConfig,

    #[serde(default)]
    pub authentication: HashMap<String, AuthConfig>,

    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    #[serde(default)]
    pub rate_limits: HashMap<String, TargetRateLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ScopeConfig {
    #[serde(default)]
    pub included_domains: Vec<String>,

    #[serde(default)]
    pub excluded_domains: Vec<String>,

    #[serde(default)]
    pub included_patterns: Vec<String>,

    #[serde(default)]
    pub excluded_patterns: Vec<String>,

    #[serde(default)]
    pub allowed_schemes: Vec<String>,

    #[serde(default = "default_true")]
    pub allow_subdomains: bool,

    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionConfig {
    #[serde(default)]
    pub paths: Vec<String>,

    #[serde(default)]
    pub path_patterns: Vec<String>,

    #[serde(default)]
    pub extensions: Vec<String>,

    #[serde(default)]
    pub parameters: Vec<String>,

    #[serde(default = "default_logout_patterns")]
    pub logout_patterns: Vec<String>,

    #[serde(default = "default_destructive_patterns")]
    pub destructive_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,

    #[serde(default)]
    pub credentials: Option<Credentials>,

    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default)]
    pub cookies: HashMap<String, String>,

    #[serde(default)]
    pub bearer_token: Option<String>,

    #[serde(default)]
    pub api_key: Option<ApiKeyConfig>,

    #[serde(default)]
    pub oauth: Option<OAuthConfig>,

    #[serde(default)]
    pub custom_auth: Option<CustomAuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub key: String,
    pub header_name: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub grant_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAuthConfig {
    pub script: String,
    #[serde(default)]
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ProxyConfig {
    #[validate(url)]
    pub url: String,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub no_proxy: Vec<String>,

    #[serde(default = "default_false")]
    pub use_system_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TargetRateLimit {
    #[validate(range(min = 1, max = 100000))]
    pub requests_per_second: u32,

    #[serde(default)]
    pub burst_size: Option<u32>,

    #[validate(range(min = 1, max = 10000))]
    #[serde(default = "default_concurrency")]
    pub max_concurrent_requests: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthType {
    None,
    Basic,
    Bearer,
    ApiKey,
    Cookie,
    OAuth2,
    Custom,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            scope: ScopeConfig::default(),
            exclusions: ExclusionConfig::default(),
            authentication: HashMap::new(),
            proxy: None,
            rate_limits: HashMap::new(),
        }
    }
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            included_domains: Vec::new(),
            excluded_domains: Vec::new(),
            included_patterns: Vec::new(),
            excluded_patterns: Vec::new(),
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_subdomains: true,
            allowed_ports: Vec::new(),
        }
    }
}

impl Default for ExclusionConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            path_patterns: Vec::new(),
            extensions: Vec::new(),
            parameters: Vec::new(),
            logout_patterns: default_logout_patterns(),
            destructive_patterns: default_destructive_patterns(),
        }
    }
}

impl ScopeConfig {
    pub fn is_in_scope(&self, url: &str) -> bool {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let host = match parsed_url.host_str() {
            Some(h) => h,
            None => return false,
        };

        let scheme = parsed_url.scheme();
        if !self.allowed_schemes.is_empty() && !self.allowed_schemes.contains(&scheme.to_string()) {
            return false;
        }

        if let Some(port) = parsed_url.port() {
            if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port) {
                return false;
            }
        }

        if !self.excluded_domains.is_empty() {
            for excluded in &self.excluded_domains {
                if self.allow_subdomains {
                    if host == excluded || host.ends_with(&format!(".{}", excluded)) {
                        return false;
                    }
                } else if host == excluded {
                    return false;
                }
            }
        }

        if !self.included_domains.is_empty() {
            let mut matched = false;
            for included in &self.included_domains {
                if self.allow_subdomains {
                    if host == included || host.ends_with(&format!(".{}", included)) {
                        matched = true;
                        break;
                    }
                } else if host == included {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }

        if !self.excluded_patterns.is_empty() {
            for pattern in &self.excluded_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(url) {
                        return false;
                    }
                }
            }
        }

        if !self.included_patterns.is_empty() {
            let mut matched = false;
            for pattern in &self.included_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(url) {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return false;
            }
        }

        true
    }
}

impl ExclusionConfig {
    pub fn is_excluded(&self, url: &str) -> bool {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let path = parsed_url.path();

        for excluded_path in &self.paths {
            if path == excluded_path || path.starts_with(excluded_path) {
                return true;
            }
        }

        for pattern in &self.path_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(path) {
                    return true;
                }
            }
        }

        for pattern in &self.logout_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(url) {
                    return true;
                }
            }
        }

        for pattern in &self.destructive_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(url) {
                    return true;
                }
            }
        }

        if let Some(extension) = path.rsplit('.').next() {
            if self.extensions.contains(&extension.to_string()) {
                return true;
            }
        }

        if let Some(query) = parsed_url.query() {
            for param in &self.parameters {
                if query.contains(&format!("{}=", param)) {
                    return true;
                }
            }
        }

        false
    }
}

impl TargetConfig {
    pub fn get_auth_for_url(&self, url: &str) -> Option<&AuthConfig> {
        let parsed_url = Url::parse(url).ok()?;
        let host = parsed_url.host_str()?;

        self.authentication.get(host).or_else(|| {
            for (pattern, auth) in &self.authentication {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(url) {
                        return Some(auth);
                    }
                }
            }
            None
        })
    }

    pub fn get_rate_limit_for_url(&self, url: &str) -> Option<&TargetRateLimit> {
        let parsed_url = Url::parse(url).ok()?;
        let host = parsed_url.host_str()?;

        self.rate_limits.get(host).or_else(|| {
            for (pattern, rate_limit) in &self.rate_limits {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(url) {
                        return Some(rate_limit);
                    }
                }
            }
            None
        })
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_concurrency() -> usize {
    50
}

fn default_logout_patterns() -> Vec<String> {
    vec![
        r".*/(logout|signout|sign-out|sign_out).*".to_string(),
        r".*/auth/(logout|signout).*".to_string(),
        r".*/user/logout.*".to_string(),
    ]
}

fn default_destructive_patterns() -> Vec<String> {
    vec![
        r".*/delete/.*".to_string(),
        r".*/remove/.*".to_string(),
        r".*/destroy/.*".to_string(),
        r".*action=(delete|remove|destroy).*".to_string(),
    ]
}
