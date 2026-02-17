// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Session state management for the AI agent.
//!
//! Tracks the conversation history, all findings, tested endpoints,
//! and detected technologies across the interactive session.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::provider::{ContentBlock, Message, Role};

/// Represents the full state of an AI testing session.
#[derive(Debug)]
pub struct Session {
    /// Target URL being tested
    pub target: String,

    /// Conversation history (messages sent to LLM)
    pub messages: Vec<Message>,

    /// All vulnerabilities discovered during this session
    pub findings: Vec<Finding>,

    /// Endpoints that have been tested and which scanners were used
    pub tested: HashMap<String, HashSet<String>>,

    /// Detected technologies
    pub technologies: Vec<String>,

    /// Discovered endpoints from crawling
    pub discovered_endpoints: Vec<String>,

    /// Cumulative token usage
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,

    /// Number of scans executed
    pub scan_count: u32,
}

/// A vulnerability finding, parsed from lonkero JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(rename = "type")]
    pub vuln_type: String,
    pub severity: String,
    pub confidence: String,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub description: String,
    pub evidence: Option<String>,
    pub cwe: Option<String>,
    pub cvss: Option<f64>,
    pub verified: bool,
    pub remediation: Option<String>,
}

impl Session {
    pub fn new(target: String) -> Self {
        Self {
            target,
            messages: Vec::new(),
            findings: Vec::new(),
            tested: HashMap::new(),
            technologies: Vec::new(),
            discovered_endpoints: Vec::new(),
            total_input_tokens: 0,
            total_output_tokens: 0,
            scan_count: 0,
        }
    }

    /// Add a user message to the conversation.
    pub fn add_user_message(&mut self, text: &str) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        });
    }

    /// Add the assistant's response to the conversation.
    pub fn add_assistant_message(&mut self, content: Vec<ContentBlock>) {
        self.messages.push(Message {
            role: Role::Assistant,
            content,
        });
    }

    /// Add a tool result to the conversation (as a user message with tool_result blocks).
    pub fn add_tool_results(&mut self, results: Vec<ContentBlock>) {
        self.messages.push(Message {
            role: Role::User,
            content: results,
        });
    }

    /// Record that an endpoint was tested with a specific scanner.
    pub fn record_test(&mut self, endpoint: &str, scanner: &str) {
        self.tested
            .entry(endpoint.to_string())
            .or_default()
            .insert(scanner.to_string());
    }

    /// Merge new findings from a scan result into the session.
    /// Returns the number of new findings added.
    /// Handles both single scan result objects and arrays of scan results.
    pub fn merge_findings(&mut self, scan_json: &serde_json::Value) -> usize {
        let mut new_count = 0;

        // Handle both array format [{"scanId":..., "vulnerabilities":[...]}]
        // and single object format {"scanId":..., "vulnerabilities":[...]}
        let scan_results: Vec<&serde_json::Value> = if let Some(arr) = scan_json.as_array() {
            arr.iter().collect()
        } else {
            vec![scan_json]
        };

        for result in &scan_results {
            if let Some(vulns) = result["vulnerabilities"].as_array() {
                for vuln in vulns {
                    let finding: Result<Finding, _> = serde_json::from_value(vuln.clone());
                    if let Ok(f) = finding {
                        // Deduplicate by (type, url, parameter)
                        let already_exists = self.findings.iter().any(|existing| {
                            existing.vuln_type == f.vuln_type
                                && existing.url == f.url
                                && existing.parameter == f.parameter
                        });
                        if !already_exists {
                            self.findings.push(f);
                            new_count += 1;
                        }
                    }
                }
            }

            // Extract discovered endpoints
            if let Some(target) = result["target"].as_str() {
                if !self.discovered_endpoints.contains(&target.to_string()) {
                    self.discovered_endpoints.push(target.to_string());
                }
            }

            // Track tested endpoints from scan metadata
            if let Some(tests_run) = result["testsRun"].as_u64() {
                if let Some(target) = result["target"].as_str() {
                    self.tested
                        .entry(target.to_string())
                        .or_default()
                        .insert(format!("scan ({} tests)", tests_run));
                }
            }
        }

        self.scan_count += 1;
        new_count
    }

    /// Get a summary of all findings for the list_findings tool.
    pub fn findings_summary(&self) -> String {
        if self.findings.is_empty() {
            return "No vulnerabilities found yet in this session.".to_string();
        }

        let mut summary = format!("=== Session Findings ({} total) ===\n\n", self.findings.len());

        // Group by severity
        let severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        for severity in &severity_order {
            let in_sev: Vec<&Finding> = self
                .findings
                .iter()
                .filter(|f| f.severity.to_uppercase() == *severity)
                .collect();

            if in_sev.is_empty() {
                continue;
            }

            summary.push_str(&format!("\n--- {} ({}) ---\n", severity, in_sev.len()));
            for f in in_sev {
                summary.push_str(&format!(
                    "  [{}/{}] {} on {}\n",
                    f.severity, f.confidence, f.vuln_type, f.url
                ));
                if let Some(ref param) = f.parameter {
                    summary.push_str(&format!("    Parameter: {}\n", param));
                }
                if let Some(ref evidence) = f.evidence {
                    let truncated = if evidence.len() > 200 {
                        format!("{}...", &evidence[..200])
                    } else {
                        evidence.clone()
                    };
                    summary.push_str(&format!("    Evidence: {}\n", truncated));
                }
            }
        }

        summary.push_str(&format!(
            "\nSession stats: {} scans run, {} endpoints tested",
            self.scan_count,
            self.tested.len()
        ));

        summary
    }

    /// Track token usage.
    pub fn track_usage(&mut self, input_tokens: u64, output_tokens: u64) {
        self.total_input_tokens += input_tokens;
        self.total_output_tokens += output_tokens;
    }
}
