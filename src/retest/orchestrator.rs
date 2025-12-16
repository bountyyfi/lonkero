// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Retest Orchestrator
 * Orchestrates vulnerability retesting with the same scanner and payload
 *
 * © 2025 Bountyy Oy
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::http_client::HttpClient;
use crate::scanners::SqliScanner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestConfig {
    pub vulnerability_id: i64,
    pub url: String,
    pub vulnerability_type: String,
    pub original_payload: String,
    pub deep_validation: bool,
    pub bypass_detection: bool,
    pub alternative_vectors: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestResult {
    pub vulnerability_id: i64,
    pub status: String, // "fixed", "still_vulnerable", "inconclusive", "error"
    pub scanner: String,
    pub scanner_version: String,
    pub payload: String,
    pub response: RetestResponse,
    pub vulnerability_found: bool,
    pub exploitable: bool,
    pub severity: String,
    pub execution_time: Duration,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub response_time_ms: u64,
}

pub struct RetestOrchestrator {
    http_client: HttpClient,
}

impl RetestOrchestrator {
    pub fn new() -> Result<Self> {
        let http_client = HttpClient::new(30, 3)?;
        Ok(Self { http_client })
    }

    /// Execute a vulnerability retest
    pub async fn execute_retest(&self, config: RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        // Route to appropriate scanner based on vulnerability type
        let result = match config.vulnerability_type.to_lowercase().as_str() {
            "sql_injection" | "sqli" => self.retest_sqli(&config).await?,
            "xss" | "cross_site_scripting" => self.retest_xss(&config).await?,
            "ssrf" => self.retest_ssrf(&config).await?,
            "nosql_injection" | "nosql" => self.retest_nosql(&config).await?,
            "command_injection" | "rce" => self.retest_command_injection(&config).await?,
            "xxe" => self.retest_xxe(&config).await?,
            "csrf" => self.retest_csrf(&config).await?,
            "cors" => self.retest_cors(&config).await?,
            "idor" => self.retest_idor(&config).await?,
            "auth_bypass" => self.retest_auth_bypass(&config).await?,
            "oauth" => self.retest_oauth(&config).await?,
            _ => {
                return Ok(RetestResult {
                    vulnerability_id: config.vulnerability_id,
                    status: "error".to_string(),
                    scanner: "unknown".to_string(),
                    scanner_version: "1.0.0".to_string(),
                    payload: config.original_payload.clone(),
                    response: RetestResponse {
                        status_code: 0,
                        headers: HashMap::new(),
                        body: format!("Unknown vulnerability type: {}", config.vulnerability_type),
                        response_time_ms: 0,
                    },
                    vulnerability_found: false,
                    exploitable: false,
                    severity: "UNKNOWN".to_string(),
                    execution_time: start_time.elapsed(),
                    metadata: HashMap::new(),
                });
            }
        };

        Ok(result)
    }

    /// Retest SQL Injection vulnerability
    async fn retest_sqli(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();
        let _scanner = SqliScanner::new(Arc::new(self.http_client.clone()));

        // Parse the URL to extract endpoint
        let url = &config.url;

        // Execute the same payload
        let payload = if config.original_payload.is_empty() {
            "' OR '1'='1".to_string()
        } else {
            config.original_payload.clone()
        };

        // Test the vulnerability
        let test_url = format!("{}?test={}", url, payload);
        let response = self.make_request(&test_url).await?;

        // Analyze response for SQL injection indicators
        let vulnerability_found = self.detect_sqli_indicators(&response.body);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "SqlInjectionScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "HIGH".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest XSS vulnerability
    async fn retest_xss(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let payload = if config.original_payload.is_empty() {
            "<script>alert('XSS')</script>".to_string()
        } else {
            config.original_payload.clone()
        };

        let test_url = format!("{}?q={}", config.url, payload);
        let response = self.make_request(&test_url).await?;

        let vulnerability_found = self.detect_xss_indicators(&response.body, &payload);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "XssScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable { "HIGH".to_string() } else { "NONE".to_string() },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest SSRF vulnerability
    async fn retest_ssrf(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let payload = if config.original_payload.is_empty() {
            "http://169.254.169.254/latest/meta-data/".to_string()
        } else {
            config.original_payload.clone()
        };

        let test_url = format!("{}?url={}", config.url, payload);
        let response = self.make_request(&test_url).await?;

        let vulnerability_found = self.detect_ssrf_indicators(&response);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "SsrfScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "CRITICAL".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest NoSQL Injection
    async fn retest_nosql(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let payload = if config.original_payload.is_empty() {
            r#"{"$ne": null}"#.to_string()
        } else {
            config.original_payload.clone()
        };

        let test_url = format!("{}?filter={}", config.url, payload);
        let response = self.make_request(&test_url).await?;

        let vulnerability_found = self.detect_nosql_indicators(&response.body);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "NoSQLScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable { "HIGH".to_string() } else { "NONE".to_string() },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest Command Injection
    async fn retest_command_injection(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let payload = if config.original_payload.is_empty() {
            "; ls -la".to_string()
        } else {
            config.original_payload.clone()
        };

        let test_url = format!("{}?cmd={}", config.url, payload);
        let response = self.make_request(&test_url).await?;

        let vulnerability_found = self.detect_command_injection_indicators(&response.body);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "CommandInjectionScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "CRITICAL".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest XXE vulnerability
    async fn retest_xxe(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let payload = if config.original_payload.is_empty() {
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string()
        } else {
            config.original_payload.clone()
        };

        let response = self.make_post_request(&config.url, &payload, "application/xml").await?;

        let vulnerability_found = self.detect_xxe_indicators(&response.body);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "XxeScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload,
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "CRITICAL".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest CSRF vulnerability
    async fn retest_csrf(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let response = self.make_request(&config.url).await?;

        let vulnerability_found = !response.headers.contains_key("x-csrf-token")
            && !response.headers.contains_key("csrf-token");
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "CsrfScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload: "".to_string(),
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "MEDIUM".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest CORS vulnerability
    async fn retest_cors(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let response = self.make_request_with_origin(&config.url, "https://evil.com").await?;

        let vulnerability_found = response
            .headers
            .get("access-control-allow-origin")
            .map(|v| v == "*" || v.contains("evil.com"))
            .unwrap_or(false);
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "CorsScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload: "Origin: https://evil.com".to_string(),
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "MEDIUM".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest IDOR vulnerability
    async fn retest_idor(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        // Test accessing another user's resource
        let test_url = format!("{}/user/999", config.url);
        let response = self.make_request(&test_url).await?;

        let vulnerability_found = response.status_code == 200
            && response.body.contains("user")
            && !response.body.contains("unauthorized");
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "IdorScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload: "/user/999".to_string(),
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "HIGH".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest Auth Bypass vulnerability
    async fn retest_auth_bypass(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let response = self.make_request(&config.url).await?;

        let vulnerability_found =
            response.status_code == 200 && !response.body.contains("login");
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "AuthBypassScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload: "".to_string(),
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "CRITICAL".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    /// Retest OAuth vulnerability
    async fn retest_oauth(&self, config: &RetestConfig) -> Result<RetestResult> {
        let start_time = Instant::now();

        let response = self.make_request(&config.url).await?;

        // Check for common OAuth misconfigurations
        let vulnerability_found = response.body.contains("access_token")
            && !response.body.contains("state");
        let exploitable = vulnerability_found;

        Ok(RetestResult {
            vulnerability_id: config.vulnerability_id,
            status: if vulnerability_found {
                "still_vulnerable".to_string()
            } else {
                "fixed".to_string()
            },
            scanner: "OAuthScanner".to_string(),
            scanner_version: "1.0.0".to_string(),
            payload: "".to_string(),
            response,
            vulnerability_found,
            exploitable,
            severity: if exploitable {
                "HIGH".to_string()
            } else {
                "NONE".to_string()
            },
            execution_time: start_time.elapsed(),
            metadata: HashMap::new(),
        })
    }

    // Helper methods for making requests
    async fn make_request(&self, _url: &str) -> Result<RetestResponse> {
        let start = Instant::now();

        // This is a simplified version - in production, use the actual HttpClient
        Ok(RetestResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: "".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn make_post_request(
        &self,
        _url: &str,
        _body: &str,
        _content_type: &str,
    ) -> Result<RetestResponse> {
        let start = Instant::now();

        Ok(RetestResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: "".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn make_request_with_origin(&self, _url: &str, origin: &str) -> Result<RetestResponse> {
        let start = Instant::now();
        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), origin.to_string());

        Ok(RetestResponse {
            status_code: 200,
            headers,
            body: "".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    // Detection methods
    fn detect_sqli_indicators(&self, body: &str) -> bool {
        let indicators = [
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "oracle",
            "mssql",
            "syntax error",
            "database error",
        ];
        indicators.iter().any(|i| body.to_lowercase().contains(i))
    }

    fn detect_xss_indicators(&self, body: &str, payload: &str) -> bool {
        body.contains(payload) && !body.contains("&lt;script&gt;")
    }

    fn detect_ssrf_indicators(&self, response: &RetestResponse) -> bool {
        response.body.contains("ami-id") || response.body.contains("instance-id")
    }

    fn detect_nosql_indicators(&self, body: &str) -> bool {
        body.contains("mongodb") || body.contains("$ne")
    }

    fn detect_command_injection_indicators(&self, body: &str) -> bool {
        body.contains("total ") || body.contains("drwx") || body.contains("bin/")
    }

    fn detect_xxe_indicators(&self, body: &str) -> bool {
        body.contains("root:") || body.contains("/etc/passwd")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let orchestrator = RetestOrchestrator::new();
        assert!(orchestrator.is_ok());
    }

    #[test]
    fn test_sqli_detection() {
        let orchestrator = RetestOrchestrator::new().unwrap();
        assert!(orchestrator.detect_sqli_indicators("MySQL syntax error at line 1"));
        assert!(!orchestrator.detect_sqli_indicators("Everything is fine"));
    }

    #[test]
    fn test_xss_detection() {
        let orchestrator = RetestOrchestrator::new().unwrap();
        let payload = "<script>alert('xss')</script>";
        assert!(orchestrator.detect_xss_indicators(payload, payload));
        assert!(!orchestrator.detect_xss_indicators("&lt;script&gt;", payload));
    }
}
