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

    /// Quick one-line status for instant user feedback.
    pub fn status_line(&self) -> String {
        let findings_str = if self.findings.is_empty() {
            "no findings yet".to_string()
        } else {
            let crit = self.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("critical")).count();
            let high = self.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("high")).count();
            let med = self.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("medium")).count();
            let low = self.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case("low") || f.severity.eq_ignore_ascii_case("info")).count();
            let mut parts = Vec::new();
            if crit > 0 { parts.push(format!("{} critical", crit)); }
            if high > 0 { parts.push(format!("{} high", high)); }
            if med > 0 { parts.push(format!("{} medium", med)); }
            if low > 0 { parts.push(format!("{} low/info", low)); }
            format!("{} findings ({})", self.findings.len(), parts.join(", "))
        };
        format!(
            "{} scans run, {} endpoints tested, {}",
            self.scan_count,
            self.tested.len(),
            findings_str,
        )
    }

    /// Track token usage.
    pub fn track_usage(&mut self, input_tokens: u64, output_tokens: u64) {
        self.total_input_tokens += input_tokens;
        self.total_output_tokens += output_tokens;
    }

    /// Compact conversation context when it gets too large.
    /// Keeps the first message (auto-mode instructions), the last few exchanges,
    /// and replaces middle messages with a summary. Returns true if compaction happened.
    pub fn compact_context(&mut self) -> bool {
        if self.messages.len() < 6 {
            return false;
        }

        // Estimate total context size (rough: sum of text content lengths)
        let total_chars: usize = self.messages.iter().map(|m| {
            m.content.iter().map(|b| match b {
                ContentBlock::Text { text } => text.len(),
                ContentBlock::ToolUse { input, .. } => input.to_string().len(),
                ContentBlock::ToolResult { content, .. } => content.len(),
                _ => 0,
            }).sum::<usize>()
        }).sum();

        // ~4 chars per token, compact if over ~80K tokens worth
        if total_chars < 300_000 {
            return false;
        }

        eprintln!("\x1b[33m  [Context compaction] Trimming {} messages ({} chars) to fit context window...\x1b[0m",
            self.messages.len(), total_chars);

        // Strategy: Keep first message + last 4 messages, replace middle with summary
        let keep_start = 1; // first message (auto-mode instructions)
        let keep_end = 4;   // last 4 messages (recent context)

        if self.messages.len() <= keep_start + keep_end {
            return false;
        }

        let first = self.messages[..keep_start].to_vec();
        let last = self.messages[self.messages.len() - keep_end..].to_vec();

        // Build a compact summary of what happened in the middle
        let summary = format!(
            "[Context compacted — {} earlier messages removed to fit context window]\n\
             Session so far: {} scans run against {}.\n\
             {}\n\
             Technologies detected: {}.\n\
             Endpoints tested: {}.\n\
             The conversation continues below with the most recent context.",
            self.messages.len() - keep_start - keep_end,
            self.scan_count,
            self.target,
            self.findings_summary(),
            if self.technologies.is_empty() { "none yet".to_string() } else { self.technologies.join(", ") },
            self.tested.keys().take(20).cloned().collect::<Vec<_>>().join(", "),
        );

        let mut compacted = first;
        compacted.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text { text: summary }],
        });
        // Need to add an assistant ack so the message alternation is valid
        compacted.push(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "Understood, continuing the assessment with the compacted context.".to_string(),
            }],
        });
        compacted.extend(last);

        let new_chars: usize = compacted.iter().map(|m| {
            m.content.iter().map(|b| match b {
                ContentBlock::Text { text } => text.len(),
                ContentBlock::ToolUse { input, .. } => input.to_string().len(),
                ContentBlock::ToolResult { content, .. } => content.len(),
                _ => 0,
            }).sum::<usize>()
        }).sum();

        eprintln!("\x1b[33m  [Context compaction] Reduced from {} to {} chars ({} messages → {})\x1b[0m",
            total_chars, new_chars, self.messages.len(), compacted.len());

        self.messages = compacted;
        true
    }
}
