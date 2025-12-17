// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * N-API Bridge for Node.js Integration
 * Exposes Rust scanners to Node.js via N-API
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan configuration passed from Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiScanConfig {
    pub scan_mode: String,
    pub timeout_secs: Option<i64>,
    pub max_retries: Option<u32>,
}

impl Default for NapiScanConfig {
    fn default() -> Self {
        Self {
            scan_mode: "normal".to_string(),
            timeout_secs: Some(30),
            max_retries: Some(3),
        }
    }
}

/// Vulnerability result returned to Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiVulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: String,
    pub description: String,
    pub evidence: Option<String>,
    pub cwe: String,
    pub cvss: f64,
    pub verified: bool,
    pub remediation: String,
    pub discovered_at: String,
}

/// Scan result returned to Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiScanResult {
    pub success: bool,
    pub resources_scanned: i32,
    pub vulnerabilities: Vec<NapiVulnerability>,
    pub error: Option<String>,
    pub findings_summary: HashMap<String, i32>,
}

/// Get scanner version
#[napi]
pub fn get_scanner_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get scanner name
#[napi]
pub fn get_scanner_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}
