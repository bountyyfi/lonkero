// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Session state management for the AI agent.
//!
//! Tracks the conversation history, all findings, tested endpoints,
//! detected technologies, hypotheses, attack plans, scope config,
//! knowledge graph, and audit log across the interactive session.
//!
//! ## Category coverage
//! - Cat 1 (Memory & Learning): Session persistence, knowledge graph, attack patterns
//! - Cat 2 (Reasoning & Planning): Hypotheses, attack plans, audit log
//! - Cat 4 (Analysis & Post-Processing): FP triage, chain synthesis, severity re-assessment
//! - Cat 6 (Security & Guardrails): Scope enforcement, output redaction
//! - Cat 7 (User Experience): Progress estimation, export conversation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::provider::{ContentBlock, Message, Role};

// ---------------------------------------------------------------------------
// Phase tracking (Cat 7: progress estimation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TestPhase {
    Recon,
    Crawling,
    TargetedScanning,
    DeepDive,
    ChainAnalysis,
    Reporting,
    Complete,
}

impl TestPhase {
    pub fn label(&self) -> &'static str {
        match self {
            TestPhase::Recon => "Reconnaissance",
            TestPhase::Crawling => "Endpoint Discovery",
            TestPhase::TargetedScanning => "Targeted Scanning",
            TestPhase::DeepDive => "Deep Dive",
            TestPhase::ChainAnalysis => "Chain Analysis",
            TestPhase::Reporting => "Reporting",
            TestPhase::Complete => "Complete",
        }
    }

    pub fn progress_pct(&self) -> u8 {
        match self {
            TestPhase::Recon => 10,
            TestPhase::Crawling => 25,
            TestPhase::TargetedScanning => 50,
            TestPhase::DeepDive => 70,
            TestPhase::ChainAnalysis => 85,
            TestPhase::Reporting => 95,
            TestPhase::Complete => 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Hypothesis tracking (Cat 2: reasoning)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub description: String,
    pub basis: String,
    pub status: HypothesisStatus,
    pub confidence: f64,
    pub tests_planned: Vec<String>,
    pub tests_completed: Vec<String>,
    pub evidence_for: Vec<String>,
    pub evidence_against: Vec<String>,
    pub created_at_scan: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HypothesisStatus {
    Proposed,
    Testing,
    Confirmed,
    Refuted,
    Inconclusive,
}

// ---------------------------------------------------------------------------
// Attack plan / DAG (Cat 2: planning)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    pub goal: String,
    pub steps: Vec<AttackStep>,
    pub current_step: usize,
    pub status: PlanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub id: usize,
    pub description: String,
    pub tool: String,
    pub tool_input: serde_json::Value,
    pub depends_on: Vec<usize>,
    pub status: StepStatus,
    pub result_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlanStatus {
    Draft,
    Active,
    Completed,
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

// ---------------------------------------------------------------------------
// Scope configuration (Cat 6: guardrails)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// Allowed URL patterns (glob-style: *.example.com, https://example.com/api/*)
    pub allowed_patterns: Vec<String>,
    /// Explicitly excluded URL patterns
    pub excluded_patterns: Vec<String>,
    /// Maximum requests per minute (0 = unlimited)
    pub rate_limit_rpm: u32,
    /// Forbidden HTTP methods (e.g. DELETE, PUT on certain paths)
    pub forbidden_methods: Vec<String>,
    /// Whether to allow testing of third-party services discovered during crawl
    pub allow_third_party: bool,
    /// Maximum scan intensity allowed
    pub max_intensity: String,
    /// Number of out-of-scope attempts blocked
    pub blocked_count: u32,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            allowed_patterns: Vec::new(),
            excluded_patterns: Vec::new(),
            rate_limit_rpm: 0,
            forbidden_methods: Vec::new(),
            allow_third_party: false,
            max_intensity: "maximum".to_string(),
            blocked_count: 0,
        }
    }
}

impl ScopeConfig {
    /// Create scope config from a target URL — auto-derives allowed patterns.
    pub fn from_target(target: &str) -> Self {
        let mut config = Self::default();
        if let Ok(url) = url::Url::parse(target) {
            if let Some(host) = url.host_str() {
                // Allow the target host and all subdomains
                config.allowed_patterns.push(format!("{}://{}", url.scheme(), host));
                config.allowed_patterns.push(format!("{}://*.{}", url.scheme(), host));
            }
        }
        config
    }

    /// Check if a URL is within scope.
    pub fn is_in_scope(&self, url: &str) -> bool {
        if self.allowed_patterns.is_empty() {
            return true; // No scope restriction
        }

        // Check exclusions first
        for pattern in &self.excluded_patterns {
            if url_matches_pattern(url, pattern) {
                return false;
            }
        }

        // Check inclusions
        for pattern in &self.allowed_patterns {
            if url_matches_pattern(url, pattern) {
                return true;
            }
        }

        false
    }

    /// Check if an intensity level is allowed.
    pub fn is_intensity_allowed(&self, intensity: &str) -> bool {
        let levels = ["minimal", "standard", "extended", "maximum"];
        let max_idx = levels.iter().position(|&l| l == self.max_intensity).unwrap_or(3);
        let req_idx = levels.iter().position(|&l| l == intensity).unwrap_or(1);
        req_idx <= max_idx
    }
}

/// Simple glob-style URL pattern matching.
fn url_matches_pattern(url: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        // Convert glob to simple prefix/suffix match
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            let matches = (prefix.is_empty() || url.starts_with(prefix))
                && (suffix.is_empty() || url.contains(suffix));
            return matches;
        }
    }
    url.starts_with(pattern)
}

// ---------------------------------------------------------------------------
// Knowledge graph (Cat 1: memory)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub url: String,
    pub method: Option<String>,
    pub parameters: Vec<String>,
    pub content_type: Option<String>,
    pub auth_required: Option<bool>,
    pub technologies: Vec<String>,
    pub related_endpoints: Vec<String>,
    pub scanners_run: Vec<String>,
    pub findings_count: usize,
}

// ---------------------------------------------------------------------------
// Audit log entry (Cat 2: reasoning trail)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub scan_number: u32,
    pub action: String,
    pub reasoning: String,
    pub outcome: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Exploit chain (Cat 4: chain synthesis)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitChain {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<ChainStep>,
    pub impact: String,
    pub overall_severity: String,
    pub overall_confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub finding_id: String,
    pub description: String,
    pub order: usize,
}

// ---------------------------------------------------------------------------
// Attack pattern memory (Cat 1: learning)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub technology: String,
    pub scan_sequence: Vec<String>,
    pub findings_produced: usize,
    pub success_rate: f64,
}

// ---------------------------------------------------------------------------
// Session (enhanced)
// ---------------------------------------------------------------------------

/// Represents the full state of an AI testing session.
#[derive(Debug)]
pub struct Session {
    // ---- Core (existing) ----
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

    // ---- Cat 1: Memory & Learning ----
    /// Knowledge graph of discovered endpoints and their relationships
    pub knowledge_graph: HashMap<String, EndpointInfo>,
    /// Attack patterns that have worked (technology → scan sequence)
    pub attack_patterns: Vec<AttackPattern>,
    /// File path for session persistence (None = not persisted)
    pub session_file: Option<String>,

    // ---- Cat 2: Reasoning & Planning ----
    /// Active hypotheses about the target
    pub hypotheses: Vec<Hypothesis>,
    /// Current attack plan (if any)
    pub attack_plan: Option<AttackPlan>,
    /// Audit log of all reasoning/decisions
    pub audit_log: Vec<AuditEntry>,

    // ---- Cat 4: Analysis ----
    /// Synthesized exploit chains
    pub exploit_chains: Vec<ExploitChain>,
    /// Findings marked as false positive by triage
    pub false_positive_ids: HashSet<String>,

    // ---- Cat 6: Security ----
    /// Scope configuration
    pub scope: ScopeConfig,
    /// Whether credential rotation was detected (401 after previously working)
    pub credential_rotation_detected: bool,

    // ---- Cat 7: UX ----
    /// Current testing phase
    pub phase: TestPhase,
    /// Token budget (0 = unlimited)
    pub token_budget: u64,
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

/// Serializable snapshot of session state for persistence (Cat 1).
#[derive(Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub target: String,
    pub findings: Vec<Finding>,
    pub tested: HashMap<String, HashSet<String>>,
    pub technologies: Vec<String>,
    pub discovered_endpoints: Vec<String>,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub scan_count: u32,
    pub knowledge_graph: HashMap<String, EndpointInfo>,
    pub attack_patterns: Vec<AttackPattern>,
    pub hypotheses: Vec<Hypothesis>,
    pub attack_plan: Option<AttackPlan>,
    pub audit_log: Vec<AuditEntry>,
    pub exploit_chains: Vec<ExploitChain>,
    pub false_positive_ids: HashSet<String>,
    pub scope: ScopeConfig,
    pub phase: TestPhase,
}

impl Session {
    pub fn new(target: String) -> Self {
        let scope = ScopeConfig::from_target(&target);
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
            // Cat 1
            knowledge_graph: HashMap::new(),
            attack_patterns: Vec::new(),
            session_file: None,
            // Cat 2
            hypotheses: Vec::new(),
            attack_plan: None,
            audit_log: Vec::new(),
            // Cat 4
            exploit_chains: Vec::new(),
            false_positive_ids: HashSet::new(),
            // Cat 6
            scope,
            credential_rotation_detected: false,
            // Cat 7
            phase: TestPhase::Recon,
            token_budget: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Core message management (existing)
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Phase management (Cat 7)
    // -----------------------------------------------------------------------

    /// Auto-advance phase based on session state.
    pub fn auto_advance_phase(&mut self) {
        let new_phase = if self.scan_count == 0 {
            TestPhase::Recon
        } else if self.discovered_endpoints.is_empty() && self.scan_count <= 2 {
            TestPhase::Crawling
        } else if self.findings.is_empty() && self.scan_count <= 8 {
            TestPhase::TargetedScanning
        } else if !self.findings.is_empty() && self.exploit_chains.is_empty() {
            TestPhase::DeepDive
        } else if !self.exploit_chains.is_empty() {
            TestPhase::ChainAnalysis
        } else {
            self.phase // keep current
        };
        if new_phase != self.phase {
            self.phase = new_phase;
        }
    }

    /// Get progress info string.
    pub fn progress_info(&self) -> String {
        let pct = self.phase.progress_pct();
        let bar_len = 20;
        let filled = (pct as usize * bar_len) / 100;
        let bar: String = (0..bar_len)
            .map(|i| if i < filled { '#' } else { '-' })
            .collect();
        format!(
            "[{}] {}% | Phase: {} | {} scans, {} findings, {} endpoints",
            bar,
            pct,
            self.phase.label(),
            self.scan_count,
            self.findings.len(),
            self.discovered_endpoints.len(),
        )
    }

    // -----------------------------------------------------------------------
    // Hypothesis management (Cat 2)
    // -----------------------------------------------------------------------

    /// Add a new hypothesis.
    pub fn add_hypothesis(&mut self, description: &str, basis: &str) -> String {
        let id = format!("H-{}", self.hypotheses.len() + 1);
        self.hypotheses.push(Hypothesis {
            id: id.clone(),
            description: description.to_string(),
            basis: basis.to_string(),
            status: HypothesisStatus::Proposed,
            confidence: 0.5,
            tests_planned: Vec::new(),
            tests_completed: Vec::new(),
            evidence_for: Vec::new(),
            evidence_against: Vec::new(),
            created_at_scan: self.scan_count,
        });
        id
    }

    /// Update a hypothesis with evidence.
    pub fn update_hypothesis(&mut self, id: &str, confirmed: bool, evidence: &str) {
        if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == id) {
            if confirmed {
                h.evidence_for.push(evidence.to_string());
                h.confidence = (h.confidence + 0.2).min(1.0);
                if h.confidence >= 0.8 {
                    h.status = HypothesisStatus::Confirmed;
                } else {
                    h.status = HypothesisStatus::Testing;
                }
            } else {
                h.evidence_against.push(evidence.to_string());
                h.confidence = (h.confidence - 0.2).max(0.0);
                if h.confidence <= 0.2 {
                    h.status = HypothesisStatus::Refuted;
                } else {
                    h.status = HypothesisStatus::Testing;
                }
            }
        }
    }

    /// Get summary of all active hypotheses.
    pub fn hypotheses_summary(&self) -> String {
        if self.hypotheses.is_empty() {
            return "No active hypotheses.".to_string();
        }
        let mut out = format!("=== Hypotheses ({}) ===\n", self.hypotheses.len());
        for h in &self.hypotheses {
            out.push_str(&format!(
                "  [{}] {:?} (confidence: {:.0}%) — {}\n",
                h.id,
                h.status,
                h.confidence * 100.0,
                h.description,
            ));
            if !h.evidence_for.is_empty() {
                out.push_str(&format!("    + {}\n", h.evidence_for.join("; ")));
            }
            if !h.evidence_against.is_empty() {
                out.push_str(&format!("    - {}\n", h.evidence_against.join("; ")));
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Attack plan management (Cat 2)
    // -----------------------------------------------------------------------

    /// Create a new attack plan.
    pub fn create_attack_plan(&mut self, goal: &str, steps: Vec<AttackStep>) {
        self.attack_plan = Some(AttackPlan {
            goal: goal.to_string(),
            steps,
            current_step: 0,
            status: PlanStatus::Active,
        });
    }

    /// Advance to next step in the plan.
    pub fn advance_plan_step(&mut self, result_summary: &str) {
        if let Some(ref mut plan) = self.attack_plan {
            if plan.current_step < plan.steps.len() {
                plan.steps[plan.current_step].status = StepStatus::Completed;
                plan.steps[plan.current_step].result_summary = Some(result_summary.to_string());
                plan.current_step += 1;
                if plan.current_step >= plan.steps.len() {
                    plan.status = PlanStatus::Completed;
                }
            }
        }
    }

    /// Get current plan status summary.
    pub fn plan_summary(&self) -> String {
        match &self.attack_plan {
            None => "No active attack plan.".to_string(),
            Some(plan) => {
                let mut out = format!(
                    "=== Attack Plan: {} ({:?}) ===\nProgress: {}/{} steps\n",
                    plan.goal,
                    plan.status,
                    plan.current_step,
                    plan.steps.len(),
                );
                for step in &plan.steps {
                    let marker = match step.status {
                        StepStatus::Completed => "[x]",
                        StepStatus::Running => "[>]",
                        StepStatus::Failed => "[!]",
                        StepStatus::Skipped => "[-]",
                        StepStatus::Pending => "[ ]",
                    };
                    out.push_str(&format!(
                        "  {} Step {}: {} (tool: {})\n",
                        marker, step.id, step.description, step.tool,
                    ));
                    if let Some(ref summary) = step.result_summary {
                        out.push_str(&format!("      Result: {}\n", summary));
                    }
                }
                out
            }
        }
    }

    // -----------------------------------------------------------------------
    // Knowledge graph (Cat 1)
    // -----------------------------------------------------------------------

    /// Add or update endpoint in knowledge graph.
    pub fn update_endpoint_info(&mut self, url: &str, info: EndpointInfo) {
        self.knowledge_graph.insert(url.to_string(), info);
    }

    /// Get knowledge graph summary.
    pub fn knowledge_graph_summary(&self) -> String {
        if self.knowledge_graph.is_empty() {
            return "Knowledge graph empty — run recon and crawl first.".to_string();
        }
        let mut out = format!(
            "=== Knowledge Graph ({} endpoints) ===\n",
            self.knowledge_graph.len()
        );
        for (url, info) in &self.knowledge_graph {
            out.push_str(&format!("  {}\n", url));
            if !info.parameters.is_empty() {
                out.push_str(&format!("    Params: {}\n", info.parameters.join(", ")));
            }
            if !info.technologies.is_empty() {
                out.push_str(&format!("    Tech: {}\n", info.technologies.join(", ")));
            }
            if info.auth_required == Some(true) {
                out.push_str("    Auth: required\n");
            }
            if info.findings_count > 0 {
                out.push_str(&format!("    Findings: {}\n", info.findings_count));
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Audit log (Cat 2)
    // -----------------------------------------------------------------------

    /// Record a reasoning/decision in the audit log.
    pub fn log_audit(&mut self, action: &str, reasoning: &str, outcome: &str) {
        self.audit_log.push(AuditEntry {
            scan_number: self.scan_count,
            action: action.to_string(),
            reasoning: reasoning.to_string(),
            outcome: outcome.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    /// Get audit log as string.
    pub fn audit_log_summary(&self) -> String {
        if self.audit_log.is_empty() {
            return "No audit entries yet.".to_string();
        }
        let mut out = format!("=== Audit Log ({} entries) ===\n", self.audit_log.len());
        for entry in &self.audit_log {
            out.push_str(&format!(
                "  [Scan #{}] {} — {} → {}\n",
                entry.scan_number, entry.action, entry.reasoning, entry.outcome,
            ));
        }
        out
    }

    // -----------------------------------------------------------------------
    // False positive triage (Cat 4)
    // -----------------------------------------------------------------------

    /// Analyze findings and flag likely false positives.
    /// Returns a summary of triage results.
    pub fn triage_false_positives(&mut self) -> String {
        let mut triaged = Vec::new();

        for finding in &self.findings {
            if self.false_positive_ids.contains(&finding.id) {
                continue;
            }
            let mut fp_score: f64 = 0.0;
            let mut reasons = Vec::new();

            // Low confidence findings are more likely FP
            if finding.confidence.eq_ignore_ascii_case("low") {
                fp_score += 0.3;
                reasons.push("low confidence");
            }

            // INFO severity with no evidence is likely noise
            if finding.severity.eq_ignore_ascii_case("info") && finding.evidence.is_none() {
                fp_score += 0.4;
                reasons.push("info-level with no evidence");
            }

            // Unverified findings are more suspect
            if !finding.verified {
                fp_score += 0.15;
                reasons.push("unverified");
            }

            // Duplicate vuln type on same endpoint with different params — possible scanner noise
            let same_type_count = self
                .findings
                .iter()
                .filter(|f| f.vuln_type == finding.vuln_type && f.url == finding.url)
                .count();
            if same_type_count > 3 {
                fp_score += 0.2;
                reasons.push("many same-type findings on endpoint");
            }

            if fp_score >= 0.5 {
                triaged.push((finding.id.clone(), fp_score, reasons.join(", ")));
            }
        }

        if triaged.is_empty() {
            return "All findings appear legitimate — no false positives flagged.".to_string();
        }

        let mut out = format!(
            "=== False Positive Triage ({} flagged) ===\n",
            triaged.len()
        );
        for (id, score, reasons) in &triaged {
            self.false_positive_ids.insert(id.clone());
            out.push_str(&format!(
                "  [FP {:.0}%] {} — {}\n",
                score * 100.0,
                id,
                reasons,
            ));
        }
        out.push_str("\nFlagged findings excluded from severity counts. Re-verify manually if needed.");
        out
    }

    /// Get findings excluding false positives.
    pub fn real_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| !self.false_positive_ids.contains(&f.id))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Exploit chain synthesis (Cat 4)
    // -----------------------------------------------------------------------

    /// Attempt to synthesize exploit chains from current findings.
    pub fn synthesize_chains(&mut self) -> String {
        let mut chains = Vec::new();

        // Pattern: Info disclosure → IDOR → Account takeover
        let info_disclosures: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| {
                f.vuln_type.contains("info_disclosure")
                    || f.vuln_type.contains("sensitive_data")
                    || f.severity.eq_ignore_ascii_case("info")
            })
            .collect();
        let idors: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("idor") || f.vuln_type.contains("bola"))
            .collect();
        let auth_issues: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| {
                f.vuln_type.contains("auth")
                    || f.vuln_type.contains("jwt")
                    || f.vuln_type.contains("session")
            })
            .collect();

        if !info_disclosures.is_empty() && !idors.is_empty() {
            let mut steps = Vec::new();
            steps.push(ChainStep {
                finding_id: info_disclosures[0].id.clone(),
                description: format!(
                    "Info disclosure reveals internal data: {}",
                    info_disclosures[0].description
                ),
                order: 1,
            });
            steps.push(ChainStep {
                finding_id: idors[0].id.clone(),
                description: format!(
                    "IDOR allows access to other users' resources: {}",
                    idors[0].description
                ),
                order: 2,
            });
            chains.push(ExploitChain {
                id: format!("CHAIN-{}", chains.len() + 1),
                name: "Info Disclosure → IDOR".to_string(),
                description: "Information leak enables targeted IDOR exploitation".to_string(),
                steps,
                impact: "Unauthorized access to other users' data".to_string(),
                overall_severity: "HIGH".to_string(),
                overall_confidence: "MEDIUM".to_string(),
            });
        }

        // Pattern: XSS → CSRF → Account takeover
        let xss_findings: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("xss"))
            .collect();
        let csrf_findings: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("csrf"))
            .collect();

        if !xss_findings.is_empty() && (!csrf_findings.is_empty() || !auth_issues.is_empty()) {
            let mut steps = Vec::new();
            steps.push(ChainStep {
                finding_id: xss_findings[0].id.clone(),
                description: format!("XSS allows script execution: {}", xss_findings[0].description),
                order: 1,
            });
            if !csrf_findings.is_empty() {
                steps.push(ChainStep {
                    finding_id: csrf_findings[0].id.clone(),
                    description: format!(
                        "CSRF enables state-changing actions: {}",
                        csrf_findings[0].description
                    ),
                    order: 2,
                });
            } else if !auth_issues.is_empty() {
                steps.push(ChainStep {
                    finding_id: auth_issues[0].id.clone(),
                    description: format!(
                        "Auth weakness enables escalation: {}",
                        auth_issues[0].description
                    ),
                    order: 2,
                });
            }
            chains.push(ExploitChain {
                id: format!("CHAIN-{}", chains.len() + 1),
                name: "XSS → Account Takeover".to_string(),
                description: "XSS chains with auth weakness for account takeover".to_string(),
                steps,
                impact: "Full account takeover of any user who visits the page".to_string(),
                overall_severity: "CRITICAL".to_string(),
                overall_confidence: "MEDIUM".to_string(),
            });
        }

        // Pattern: SSRF → Cloud metadata → Credential theft
        let ssrf_findings: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("ssrf"))
            .collect();

        if !ssrf_findings.is_empty() {
            let mut steps = Vec::new();
            steps.push(ChainStep {
                finding_id: ssrf_findings[0].id.clone(),
                description: format!("SSRF allows internal requests: {}", ssrf_findings[0].description),
                order: 1,
            });
            steps.push(ChainStep {
                finding_id: "potential".to_string(),
                description: "Cloud metadata endpoint (169.254.169.254) may expose credentials"
                    .to_string(),
                order: 2,
            });
            chains.push(ExploitChain {
                id: format!("CHAIN-{}", chains.len() + 1),
                name: "SSRF → Cloud Credential Theft".to_string(),
                description: "SSRF can pivot to cloud metadata for credential extraction"
                    .to_string(),
                steps,
                impact: "Full cloud infrastructure compromise via stolen credentials".to_string(),
                overall_severity: "CRITICAL".to_string(),
                overall_confidence: "LOW".to_string(),
            });
        }

        // Pattern: Open Redirect → OAuth token theft
        let redirect_findings: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("redirect"))
            .collect();
        let oauth_findings: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.vuln_type.contains("oauth"))
            .collect();

        if !redirect_findings.is_empty() && !oauth_findings.is_empty() {
            chains.push(ExploitChain {
                id: format!("CHAIN-{}", chains.len() + 1),
                name: "Open Redirect → OAuth Token Theft".to_string(),
                description: "Open redirect in OAuth flow enables token interception".to_string(),
                steps: vec![
                    ChainStep {
                        finding_id: redirect_findings[0].id.clone(),
                        description: "Open redirect manipulates OAuth callback".to_string(),
                        order: 1,
                    },
                    ChainStep {
                        finding_id: oauth_findings[0].id.clone(),
                        description: "OAuth token sent to attacker-controlled redirect".to_string(),
                        order: 2,
                    },
                ],
                impact: "OAuth token theft leading to account takeover".to_string(),
                overall_severity: "CRITICAL".to_string(),
                overall_confidence: "MEDIUM".to_string(),
            });
        }

        self.exploit_chains = chains;

        if self.exploit_chains.is_empty() {
            return "No exploit chains identified from current findings. More findings may reveal chainable vulnerabilities.".to_string();
        }

        let mut out = format!(
            "=== Exploit Chains ({} identified) ===\n",
            self.exploit_chains.len()
        );
        for chain in &self.exploit_chains {
            out.push_str(&format!(
                "\n  [{}] {} (Severity: {}, Confidence: {})\n",
                chain.id, chain.name, chain.overall_severity, chain.overall_confidence,
            ));
            out.push_str(&format!("    Impact: {}\n", chain.impact));
            for step in &chain.steps {
                out.push_str(&format!(
                    "    {}. {} (finding: {})\n",
                    step.order, step.description, step.finding_id,
                ));
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Severity re-assessment (Cat 4)
    // -----------------------------------------------------------------------

    /// Re-assess finding severities based on context (exploit chains, scope, etc).
    pub fn reassess_severities(&mut self) -> String {
        let mut changes = Vec::new();

        // Findings that participate in chains get elevated
        let chain_finding_ids: HashSet<String> = self
            .exploit_chains
            .iter()
            .flat_map(|c| c.steps.iter().map(|s| s.finding_id.clone()))
            .collect();

        for finding in &mut self.findings {
            // Elevate findings that are part of exploit chains
            if chain_finding_ids.contains(&finding.id) {
                let old = finding.severity.clone();
                if finding.severity.eq_ignore_ascii_case("low") {
                    finding.severity = "MEDIUM".to_string();
                    changes.push(format!(
                        "{}: {} → MEDIUM (part of exploit chain)",
                        finding.id, old
                    ));
                } else if finding.severity.eq_ignore_ascii_case("medium") {
                    finding.severity = "HIGH".to_string();
                    changes.push(format!(
                        "{}: {} → HIGH (part of exploit chain)",
                        finding.id, old
                    ));
                }
            }

            // Verified findings with high CVSS but low severity get elevated
            if finding.verified {
                if let Some(cvss) = finding.cvss {
                    if cvss >= 7.0 && finding.severity.eq_ignore_ascii_case("medium") {
                        let old = finding.severity.clone();
                        finding.severity = "HIGH".to_string();
                        changes.push(format!(
                            "{}: {} → HIGH (CVSS {:.1}, verified)",
                            finding.id, old, cvss
                        ));
                    }
                }
            }
        }

        if changes.is_empty() {
            "No severity changes after re-assessment.".to_string()
        } else {
            let mut out = format!(
                "=== Severity Re-assessment ({} changes) ===\n",
                changes.len()
            );
            for change in &changes {
                out.push_str(&format!("  {}\n", change));
            }
            out
        }
    }

    // -----------------------------------------------------------------------
    // Output redaction (Cat 6)
    // -----------------------------------------------------------------------

    /// Redact sensitive data from a string (credentials, tokens, keys).
    pub fn redact_sensitive(input: &str) -> String {
        let mut output = input.to_string();

        // Redact common secret patterns
        let patterns: &[(&str, &str)] = &[
            (r#"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#, "$1=***REDACTED***"),
            (r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?(\S{4,})['"]?"#, "$1=***REDACTED***"),
            (r#"(?i)(secret|token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9_\-.]{20,})['"]?"#, "$1=***REDACTED***"),
            (r#"(?i)(authorization:\s*bearer\s+)([a-zA-Z0-9_\-.]+)"#, "${1}***REDACTED***"),
            (r#"(?i)(aws[_\-]?(?:access|secret)[_\-]?(?:key|id))\s*[:=]\s*['"]?([A-Za-z0-9/+=]{16,})['"]?"#, "$1=***REDACTED***"),
        ];

        for (pattern, replacement) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                output = re.replace_all(&output, *replacement).to_string();
            }
        }

        output
    }

    // -----------------------------------------------------------------------
    // Session persistence (Cat 1)
    // -----------------------------------------------------------------------

    /// Save session state to a JSON file.
    pub fn save_to_file(&self, path: &str) -> Result<String, String> {
        let snapshot = SessionSnapshot {
            target: self.target.clone(),
            findings: self.findings.clone(),
            tested: self.tested.clone(),
            technologies: self.technologies.clone(),
            discovered_endpoints: self.discovered_endpoints.clone(),
            total_input_tokens: self.total_input_tokens,
            total_output_tokens: self.total_output_tokens,
            scan_count: self.scan_count,
            knowledge_graph: self.knowledge_graph.clone(),
            attack_patterns: self.attack_patterns.clone(),
            hypotheses: self.hypotheses.clone(),
            attack_plan: self.attack_plan.clone(),
            audit_log: self.audit_log.clone(),
            exploit_chains: self.exploit_chains.clone(),
            false_positive_ids: self.false_positive_ids.clone(),
            scope: self.scope.clone(),
            phase: self.phase,
        };

        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| format!("Serialization error: {}", e))?;
        std::fs::write(path, &json).map_err(|e| format!("File write error: {}", e))?;
        Ok(format!(
            "Session saved to {} ({} findings, {} scans, {} hypotheses, {} chains)",
            path,
            self.findings.len(),
            self.scan_count,
            self.hypotheses.len(),
            self.exploit_chains.len(),
        ))
    }

    /// Load session state from a JSON file.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("File read error: {}", e))?;
        let snapshot: SessionSnapshot =
            serde_json::from_str(&json).map_err(|e| format!("Parse error: {}", e))?;

        let mut session = Session::new(snapshot.target);
        session.findings = snapshot.findings;
        session.tested = snapshot.tested;
        session.technologies = snapshot.technologies;
        session.discovered_endpoints = snapshot.discovered_endpoints;
        session.total_input_tokens = snapshot.total_input_tokens;
        session.total_output_tokens = snapshot.total_output_tokens;
        session.scan_count = snapshot.scan_count;
        session.knowledge_graph = snapshot.knowledge_graph;
        session.attack_patterns = snapshot.attack_patterns;
        session.hypotheses = snapshot.hypotheses;
        session.attack_plan = snapshot.attack_plan;
        session.audit_log = snapshot.audit_log;
        session.exploit_chains = snapshot.exploit_chains;
        session.false_positive_ids = snapshot.false_positive_ids;
        session.scope = snapshot.scope;
        session.phase = snapshot.phase;
        session.session_file = Some(path.to_string());
        Ok(session)
    }

    // -----------------------------------------------------------------------
    // Export conversation (Cat 7)
    // -----------------------------------------------------------------------

    /// Export the full conversation history as markdown.
    pub fn export_conversation(&self) -> String {
        let mut md = format!("# Lonkero AI Session — {}\n\n", self.target);
        md.push_str(&format!(
            "**Scans:** {} | **Findings:** {} | **Tokens:** {} in / {} out\n\n---\n\n",
            self.scan_count,
            self.findings.len(),
            self.total_input_tokens,
            self.total_output_tokens,
        ));

        for msg in &self.messages {
            let role_label = match msg.role {
                Role::User => "**User**",
                Role::Assistant => "**Lonkero AI**",
            };
            md.push_str(&format!("### {}\n\n", role_label));

            for block in &msg.content {
                match block {
                    ContentBlock::Text { text } => {
                        md.push_str(&Session::redact_sensitive(text));
                        md.push_str("\n\n");
                    }
                    ContentBlock::ToolUse { name, input, .. } => {
                        md.push_str(&format!(
                            "> **Tool call:** `{}` with `{}`\n\n",
                            name,
                            serde_json::to_string(input).unwrap_or_default()
                        ));
                    }
                    ContentBlock::ToolResult { content, is_error, .. } => {
                        let prefix = if *is_error == Some(true) {
                            "> **Tool error:**"
                        } else {
                            "> **Tool result:**"
                        };
                        let truncated = if content.len() > 500 {
                            format!("{}...(truncated)", &content[..500])
                        } else {
                            content.clone()
                        };
                        md.push_str(&format!("{} {}\n\n", prefix, truncated));
                    }
                    _ => {}
                }
            }
            md.push_str("---\n\n");
        }

        // Append findings summary
        md.push_str("## Findings Summary\n\n");
        md.push_str(&self.findings_summary());
        md.push('\n');

        // Append chain analysis if available
        if !self.exploit_chains.is_empty() {
            md.push_str("\n## Exploit Chains\n\n");
            for chain in &self.exploit_chains {
                md.push_str(&format!(
                    "### {} ({})\n\n{}\n\n**Impact:** {}\n\n",
                    chain.name, chain.overall_severity, chain.description, chain.impact,
                ));
            }
        }

        md
    }

    // -----------------------------------------------------------------------
    // Attack pattern learning (Cat 1)
    // -----------------------------------------------------------------------

    /// Record a successful attack pattern.
    pub fn record_attack_pattern(&mut self, technology: &str, scan_sequence: Vec<String>, findings_count: usize) {
        // Update existing pattern or create new
        if let Some(pattern) = self
            .attack_patterns
            .iter_mut()
            .find(|p| p.technology == technology)
        {
            let total_runs = (1.0 / pattern.success_rate).round() as usize;
            let new_total = total_runs + 1;
            let new_successes = if findings_count > 0 {
                (pattern.success_rate * total_runs as f64) as usize + 1
            } else {
                (pattern.success_rate * total_runs as f64) as usize
            };
            pattern.success_rate = new_successes as f64 / new_total as f64;
            pattern.findings_produced += findings_count;
            if findings_count > 0 {
                pattern.scan_sequence = scan_sequence;
            }
        } else {
            self.attack_patterns.push(AttackPattern {
                technology: technology.to_string(),
                scan_sequence,
                findings_produced: findings_count,
                success_rate: if findings_count > 0 { 1.0 } else { 0.0 },
            });
        }
    }

    /// Get recommended scan sequence for a technology based on past patterns.
    pub fn get_recommended_sequence(&self, technology: &str) -> Option<&Vec<String>> {
        self.attack_patterns
            .iter()
            .filter(|p| p.technology == technology && p.success_rate > 0.3)
            .max_by(|a, b| a.success_rate.partial_cmp(&b.success_rate).unwrap_or(std::cmp::Ordering::Equal))
            .map(|p| &p.scan_sequence)
    }

    // -----------------------------------------------------------------------
    // Scope checking (Cat 6)
    // -----------------------------------------------------------------------

    /// Check if a URL is within the configured scope. Returns Ok(()) or an error message.
    pub fn check_scope(&mut self, url: &str) -> Result<(), String> {
        if self.scope.is_in_scope(url) {
            Ok(())
        } else {
            self.scope.blocked_count += 1;
            Err(format!(
                "OUT OF SCOPE: {} is not within the allowed scope. Blocked {} total out-of-scope attempts.",
                url, self.scope.blocked_count,
            ))
        }
    }

    /// Check if an intensity level is within scope limits.
    pub fn check_intensity(&self, intensity: &str) -> Result<(), String> {
        if self.scope.is_intensity_allowed(intensity) {
            Ok(())
        } else {
            Err(format!(
                "Intensity '{}' exceeds scope limit '{}'. Use a lower intensity.",
                intensity, self.scope.max_intensity,
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Token budget (Cat 5/7)
    // -----------------------------------------------------------------------

    /// Check if we're within token budget. Returns remaining tokens or error.
    pub fn check_token_budget(&self) -> Result<u64, String> {
        if self.token_budget == 0 {
            return Ok(u64::MAX); // Unlimited
        }
        let used = self.total_input_tokens + self.total_output_tokens;
        if used >= self.token_budget {
            Err(format!(
                "Token budget exhausted: used {} of {} tokens",
                used, self.token_budget,
            ))
        } else {
            Ok(self.token_budget - used)
        }
    }

    // -----------------------------------------------------------------------
    // Findings & merging (existing, preserved)
    // -----------------------------------------------------------------------

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

        // Auto-advance phase after merging
        self.auto_advance_phase();

        new_count
    }

    /// Get a summary of all findings for the list_findings tool.
    pub fn findings_summary(&self) -> String {
        if self.findings.is_empty() {
            return "No vulnerabilities found yet in this session.".to_string();
        }

        let real_count = self.real_findings().len();
        let fp_count = self.false_positive_ids.len();
        let mut summary = format!(
            "=== Session Findings ({} total, {} real, {} FP-flagged) ===\n\n",
            self.findings.len(),
            real_count,
            fp_count,
        );

        // Group by severity
        let severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        for severity in &severity_order {
            let in_sev: Vec<&Finding> = self
                .real_findings()
                .into_iter()
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

        // Show chains if any
        if !self.exploit_chains.is_empty() {
            summary.push_str(&format!(
                "\nExploit chains: {} identified",
                self.exploit_chains.len()
            ));
        }

        // Show active hypotheses
        let active_h = self
            .hypotheses
            .iter()
            .filter(|h| h.status == HypothesisStatus::Testing || h.status == HypothesisStatus::Proposed)
            .count();
        if active_h > 0 {
            summary.push_str(&format!("\nActive hypotheses: {}", active_h));
        }

        summary
    }

    /// Quick one-line status for instant user feedback.
    pub fn status_line(&self) -> String {
        let findings_str = if self.findings.is_empty() {
            "no findings yet".to_string()
        } else {
            let crit = self.real_findings().iter().filter(|f| f.severity.eq_ignore_ascii_case("critical")).count();
            let high = self.real_findings().iter().filter(|f| f.severity.eq_ignore_ascii_case("high")).count();
            let med = self.real_findings().iter().filter(|f| f.severity.eq_ignore_ascii_case("medium")).count();
            let low = self.real_findings().iter().filter(|f| f.severity.eq_ignore_ascii_case("low") || f.severity.eq_ignore_ascii_case("info")).count();
            let mut parts = Vec::new();
            if crit > 0 { parts.push(format!("{} critical", crit)); }
            if high > 0 { parts.push(format!("{} high", high)); }
            if med > 0 { parts.push(format!("{} medium", med)); }
            if low > 0 { parts.push(format!("{} low/info", low)); }
            format!("{} findings ({})", self.real_findings().len(), parts.join(", "))
        };
        format!(
            "{} | {} scans, {} endpoints, {}",
            self.phase.label(),
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
             Active hypotheses: {}.\n\
             Exploit chains: {}.\n\
             The conversation continues below with the most recent context.",
            self.messages.len() - keep_start - keep_end,
            self.scan_count,
            self.target,
            self.findings_summary(),
            if self.technologies.is_empty() { "none yet".to_string() } else { self.technologies.join(", ") },
            self.tested.keys().take(20).cloned().collect::<Vec<_>>().join(", "),
            self.hypotheses.iter().filter(|h| h.status == HypothesisStatus::Testing).count(),
            self.exploit_chains.len(),
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
