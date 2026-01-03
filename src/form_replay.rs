// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Form Replay System for Security Testing
//!
//! This module provides a comprehensive system for recording and replaying complex
//! form submission sequences. It is designed to handle:
//!
//! - Multi-step wizard forms (e.g., checkout flows, registration wizards)
//! - Forms with dynamic tokens (CSRF, nonce, timestamps)
//! - State-dependent form sequences that must run in order
//! - Parameter injection for security testing
//!
//! # Architecture
//!
//! The system consists of four main components:
//!
//! - [`FormSubmission`]: Represents a single form submission with all its data
//! - [`FormSequence`]: An ordered list of submissions that must run together
//! - [`FormRecorder`]: Records form interactions during headless crawling
//! - [`FormReplayer`]: Replays recorded sequences with payload injection
//!
//! # Example Usage
//!
//! ```ignore
//! use lonkero::form_replay::{FormRecorder, FormReplayer, FormReplayConfig};
//!
//! // Create a recorder during crawl
//! let mut recorder = FormRecorder::new();
//!
//! // Record form submissions as they happen
//! recorder.record_submission(submission);
//!
//! // After crawl, get recorded sequences
//! let sequences = recorder.finalize();
//!
//! // Create a replayer for security testing
//! let replayer = FormReplayer::new(config);
//!
//! // Replay with injection
//! let results = replayer.replay_with_injection(&sequence, "email", "<script>alert(1)</script>").await?;
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::crawler::{DiscoveredForm, FormInput};
use crate::headless_crawler::{CsrfTokenInfo, FormSubmissionResult, HeadlessCrawler};

// ============================================================================
// Core Data Structures
// ============================================================================

/// A single form submission with all captured data
///
/// This structure captures everything needed to replay a form submission:
/// - The target URL and HTTP method
/// - All form fields with their values
/// - HTTP headers that were present
/// - Hidden fields and their values
/// - Information about dynamic tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormSubmission {
    /// Unique identifier for this submission
    pub id: String,

    /// Form action URL (where the form submits to)
    pub action_url: String,

    /// HTTP method (POST, GET, PUT, etc.)
    pub method: String,

    /// All form fields with their names, types, and values
    pub fields: Vec<FormField>,

    /// HTTP headers captured during submission
    pub headers: HashMap<String, String>,

    /// Cookies present at time of submission
    pub cookies: HashMap<String, String>,

    /// The page URL where the form was found
    pub source_url: String,

    /// Timestamp when this submission was recorded
    pub recorded_at: String,

    /// Response URL after submission (for detecting redirects)
    pub response_url: Option<String>,

    /// Response status code if available
    pub response_status: Option<u16>,

    /// Sequence index if part of a multi-step flow (0-based)
    pub sequence_index: Option<usize>,

    /// Whether this submission is part of a detected wizard flow
    pub is_wizard_step: bool,
}

/// A form field with metadata for replay and injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    /// Field name attribute
    pub name: String,

    /// Input type (text, email, password, hidden, select, etc.)
    pub field_type: String,

    /// Current/recorded value
    pub value: Option<String>,

    /// Available options for select/radio fields
    pub options: Option<Vec<String>>,

    /// Whether the field is required
    pub required: bool,

    /// Whether this field appears to be a dynamic token (CSRF, nonce)
    pub is_dynamic_token: bool,

    /// Token type if detected (csrf, nonce, timestamp, session)
    pub token_type: Option<TokenType>,

    /// Whether this field is safe to inject payloads into
    pub is_injectable: bool,

    /// Field validation pattern if detected (email, phone, etc.)
    pub validation_pattern: Option<String>,
}

/// Types of dynamic tokens that need special handling
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// CSRF/XSRF protection token
    Csrf,
    /// Nonce value (single-use)
    Nonce,
    /// Timestamp-based token
    Timestamp,
    /// Session-bound token
    Session,
    /// Captcha challenge token
    Captcha,
    /// Unknown token type
    Unknown,
}

impl FormSubmission {
    /// Create a new form submission
    pub fn new(action_url: String, method: String, source_url: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            action_url,
            method,
            fields: Vec::new(),
            headers: HashMap::new(),
            cookies: HashMap::new(),
            source_url,
            recorded_at: chrono::Utc::now().to_rfc3339(),
            response_url: None,
            response_status: None,
            sequence_index: None,
            is_wizard_step: false,
        }
    }

    /// Create from a DiscoveredForm
    pub fn from_discovered_form(form: &DiscoveredForm) -> Self {
        let mut submission = Self::new(
            form.action.clone(),
            form.method.clone(),
            form.discovered_at.clone(),
        );

        for input in &form.inputs {
            submission.fields.push(FormField::from_form_input(input));
        }

        submission
    }

    /// Add a field to the submission
    pub fn add_field(&mut self, field: FormField) {
        self.fields.push(field);
    }

    /// Get all injectable fields (safe for payload injection)
    pub fn get_injectable_fields(&self) -> Vec<&FormField> {
        self.fields.iter().filter(|f| f.is_injectable).collect()
    }

    /// Get all dynamic token fields
    pub fn get_token_fields(&self) -> Vec<&FormField> {
        self.fields.iter().filter(|f| f.is_dynamic_token).collect()
    }

    /// Clone with a field value modified (for injection testing)
    pub fn with_modified_field(&self, field_name: &str, new_value: &str) -> Self {
        let mut cloned = self.clone();
        for field in &mut cloned.fields {
            if field.name == field_name {
                field.value = Some(new_value.to_string());
                break;
            }
        }
        cloned
    }

    /// Get all fields as key-value pairs for submission
    pub fn to_form_data(&self) -> Vec<(String, String)> {
        self.fields
            .iter()
            .filter_map(|f| f.value.as_ref().map(|v| (f.name.clone(), v.clone())))
            .collect()
    }

    /// Generate a signature for deduplication
    pub fn signature(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.action_url.hash(&mut hasher);
        // Normalize method to uppercase for consistent hashing (POST == post)
        self.method.to_uppercase().hash(&mut hasher);

        // Sort field names for consistent hashing
        let mut names: Vec<_> = self.fields.iter().map(|f| &f.name).collect();
        names.sort();
        for name in names {
            name.hash(&mut hasher);
        }

        hasher.finish()
    }
}

impl FormField {
    /// Create a new form field
    pub fn new(name: String, field_type: String) -> Self {
        let is_dynamic_token = Self::detect_token_field(&name, &field_type);
        let token_type = if is_dynamic_token {
            Some(Self::classify_token(&name))
        } else {
            None
        };
        let is_injectable = !is_dynamic_token && field_type != "hidden";

        Self {
            name,
            field_type,
            value: None,
            options: None,
            required: false,
            is_dynamic_token,
            token_type,
            is_injectable,
            validation_pattern: None,
        }
    }

    /// Create from a FormInput
    pub fn from_form_input(input: &FormInput) -> Self {
        let is_dynamic_token = Self::detect_token_field(&input.name, &input.input_type);
        let token_type = if is_dynamic_token {
            Some(Self::classify_token(&input.name))
        } else {
            None
        };
        // Injectable if not a token and not a hidden field (unless it's a regular hidden field)
        let is_injectable = !is_dynamic_token
            && (input.input_type != "hidden" || !Self::is_system_field(&input.name));

        Self {
            name: input.name.clone(),
            field_type: input.input_type.clone(),
            value: input.value.clone(),
            options: input.options.clone(),
            required: input.required,
            is_dynamic_token,
            token_type,
            is_injectable,
            validation_pattern: Self::detect_validation_pattern(&input.name, &input.input_type),
        }
    }

    /// Detect if a field is likely a dynamic token based on its name
    fn detect_token_field(name: &str, field_type: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Common CSRF/token patterns
        let token_patterns = [
            "csrf",
            "_csrf",
            "xsrf",
            "_xsrf",
            "_token",
            "authenticity_token",
            "verification_token",
            "requestverificationtoken",
            "__requestverificationtoken",
            "csrfmiddlewaretoken",
            "anti-forgery",
            "antiforgery",
            "form_token",
            "formtoken",
            "security_token",
            "nonce",
            "_nonce",
            "__nonce",
            "timestamp",
            "_timestamp",
            "ts",
            "captcha",
            "recaptcha",
            "hcaptcha",
        ];

        // Check name patterns
        for pattern in &token_patterns {
            if name_lower.contains(pattern) {
                return true;
            }
        }

        // Hidden fields with UUID-like or long random values
        if field_type == "hidden" {
            // Check for patterns that suggest dynamic tokens
            if name_lower.ends_with("_token") || name_lower.ends_with("token") {
                return true;
            }
        }

        false
    }

    /// Classify the type of token based on field name
    fn classify_token(name: &str) -> TokenType {
        let name_lower = name.to_lowercase();

        if name_lower.contains("csrf")
            || name_lower.contains("xsrf")
            || name_lower.contains("authenticity")
            || name_lower.contains("verification")
            || name_lower.contains("antiforgery")
        {
            TokenType::Csrf
        } else if name_lower.contains("nonce") {
            TokenType::Nonce
        } else if name_lower.contains("timestamp") || name_lower.contains("ts") {
            TokenType::Timestamp
        } else if name_lower.contains("session") {
            TokenType::Session
        } else if name_lower.contains("captcha") {
            TokenType::Captcha
        } else {
            TokenType::Unknown
        }
    }

    /// Check if this is a system/framework field that shouldn't be modified
    fn is_system_field(name: &str) -> bool {
        let name_lower = name.to_lowercase();
        name_lower.starts_with("__")
            || name_lower.contains("viewstate")
            || name_lower.contains("eventvalidation")
            || name_lower == "utf8"
    }

    /// Detect validation pattern based on field name and type
    fn detect_validation_pattern(name: &str, field_type: &str) -> Option<String> {
        let name_lower = name.to_lowercase();

        if field_type == "email" || name_lower.contains("email") {
            Some("email".to_string())
        } else if field_type == "tel"
            || name_lower.contains("phone")
            || name_lower.contains("mobile")
        {
            Some("phone".to_string())
        } else if field_type == "url"
            || name_lower.contains("url")
            || name_lower.contains("website")
        {
            Some("url".to_string())
        } else if name_lower.contains("zip") || name_lower.contains("postal") {
            Some("postal_code".to_string())
        } else if name_lower.contains("credit") || name_lower.contains("card_number") {
            Some("credit_card".to_string())
        } else {
            None
        }
    }
}

// ============================================================================
// Form Sequence - Multi-Step Flow
// ============================================================================

/// An ordered sequence of form submissions that must run together
///
/// Form sequences represent multi-step flows like:
/// - Checkout processes (cart -> shipping -> payment -> confirm)
/// - Registration wizards (basic info -> preferences -> verification)
/// - Multi-page surveys
///
/// The sequence tracks dependencies and ensures proper ordering during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormSequence {
    /// Unique identifier for this sequence
    pub id: String,

    /// Human-readable name for the sequence
    pub name: String,

    /// Ordered list of form submissions
    pub submissions: Vec<FormSubmission>,

    /// Initial URL where the sequence starts
    pub start_url: String,

    /// Final URL after completing the sequence
    pub end_url: Option<String>,

    /// Whether this sequence was auto-detected as a wizard
    pub is_wizard: bool,

    /// Detected flow type (checkout, registration, survey, etc.)
    pub flow_type: Option<FlowType>,

    /// Total number of steps in the sequence
    pub step_count: usize,

    /// State that must be restored before replay
    pub initial_state: SequenceState,

    /// Timestamp when this sequence was recorded
    pub recorded_at: String,
}

/// Type of form flow detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlowType {
    /// E-commerce checkout flow
    Checkout,
    /// User registration/signup
    Registration,
    /// Login/authentication flow
    Login,
    /// Password reset flow
    PasswordReset,
    /// Profile update/settings
    ProfileUpdate,
    /// Multi-page survey or questionnaire
    Survey,
    /// Generic multi-step wizard
    Wizard,
    /// Unknown flow type
    Unknown,
}

/// State required before replaying a sequence
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SequenceState {
    /// Cookies that must be set
    pub cookies: HashMap<String, String>,

    /// LocalStorage items
    pub local_storage: HashMap<String, String>,

    /// SessionStorage items
    pub session_storage: HashMap<String, String>,

    /// Auth token if authenticated
    pub auth_token: Option<String>,

    /// Any custom state data
    pub custom: HashMap<String, String>,
}

impl FormSequence {
    /// Create a new empty sequence
    pub fn new(name: String, start_url: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            submissions: Vec::new(),
            start_url,
            end_url: None,
            is_wizard: false,
            flow_type: None,
            step_count: 0,
            initial_state: SequenceState::default(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add a submission to the sequence
    pub fn add_submission(&mut self, mut submission: FormSubmission) {
        submission.sequence_index = Some(self.submissions.len());
        submission.is_wizard_step = self.is_wizard;
        self.submissions.push(submission);
        self.step_count = self.submissions.len();
    }

    /// Get all injectable fields across all submissions
    pub fn get_all_injectable_fields(&self) -> Vec<(&FormSubmission, &FormField)> {
        self.submissions
            .iter()
            .flat_map(|s| {
                s.fields
                    .iter()
                    .filter(|f| f.is_injectable)
                    .map(move |f| (s, f))
            })
            .collect()
    }

    /// Detect the flow type based on URLs and field patterns
    pub fn detect_flow_type(&mut self) {
        let all_urls: Vec<&str> = self
            .submissions
            .iter()
            .map(|s| s.action_url.as_str())
            .chain(std::iter::once(self.start_url.as_str()))
            .collect();

        let url_text = all_urls.join(" ").to_lowercase();

        // Check field names across all submissions
        let all_fields: Vec<&str> = self
            .submissions
            .iter()
            .flat_map(|s| s.fields.iter().map(|f| f.name.as_str()))
            .collect();
        let field_text = all_fields.join(" ").to_lowercase();

        // Detect checkout flow
        if url_text.contains("checkout")
            || url_text.contains("cart")
            || url_text.contains("payment")
            || url_text.contains("order")
            || field_text.contains("credit")
            || field_text.contains("shipping")
        {
            self.flow_type = Some(FlowType::Checkout);
        }
        // Detect registration flow
        else if url_text.contains("register")
            || url_text.contains("signup")
            || url_text.contains("create-account")
            || (field_text.contains("password") && field_text.contains("confirm"))
        {
            self.flow_type = Some(FlowType::Registration);
        }
        // Detect login flow
        else if url_text.contains("login")
            || url_text.contains("signin")
            || url_text.contains("authenticate")
        {
            self.flow_type = Some(FlowType::Login);
        }
        // Detect password reset
        else if url_text.contains("password")
            && (url_text.contains("reset") || url_text.contains("forgot"))
        {
            self.flow_type = Some(FlowType::PasswordReset);
        }
        // Detect profile update
        else if url_text.contains("profile")
            || url_text.contains("settings")
            || url_text.contains("account")
        {
            self.flow_type = Some(FlowType::ProfileUpdate);
        }
        // Detect survey
        else if url_text.contains("survey")
            || url_text.contains("questionnaire")
            || url_text.contains("quiz")
        {
            self.flow_type = Some(FlowType::Survey);
        }
        // Multi-step wizard (generic)
        else if self.submissions.len() > 1 && self.is_wizard {
            self.flow_type = Some(FlowType::Wizard);
        } else {
            self.flow_type = Some(FlowType::Unknown);
        }
    }

    /// Check if this sequence requires CSRF token refresh between steps
    pub fn requires_csrf_refresh(&self) -> bool {
        self.submissions.iter().any(|s| {
            s.fields
                .iter()
                .any(|f| f.token_type == Some(TokenType::Csrf))
        })
    }
}

// ============================================================================
// Form Recorder - Records Form Interactions During Crawl
// ============================================================================

/// Configuration for form recording
#[derive(Debug, Clone)]
pub struct FormRecorderConfig {
    /// Maximum submissions to record per form
    pub max_submissions_per_form: usize,

    /// Maximum total submissions to record
    pub max_total_submissions: usize,

    /// Whether to detect wizard flows automatically
    pub detect_wizards: bool,

    /// Time window to consider submissions as part of same flow (seconds)
    pub flow_detection_window_secs: u64,

    /// Whether to record hidden field values
    pub record_hidden_fields: bool,

    /// Whether to capture request headers
    pub capture_headers: bool,
}

impl Default for FormRecorderConfig {
    fn default() -> Self {
        Self {
            max_submissions_per_form: 10,
            max_total_submissions: 100,
            detect_wizards: true,
            flow_detection_window_secs: 300, // 5 minutes
            record_hidden_fields: true,
            capture_headers: true,
        }
    }
}

/// Records form interactions during headless crawling
///
/// The FormRecorder is designed to be integrated with the HeadlessCrawler
/// to capture form submissions as they occur during a crawl.
#[derive(Debug)]
pub struct FormRecorder {
    /// Configuration
    config: FormRecorderConfig,

    /// All recorded submissions
    submissions: Vec<FormSubmission>,

    /// Detected sequences (wizard flows)
    sequences: Vec<FormSequence>,

    /// Form signatures seen (for deduplication)
    seen_signatures: HashSet<u64>,

    /// Active wizard detection state
    active_flow: Option<ActiveFlowState>,

    /// Current session state
    current_state: SequenceState,

    /// Submission timestamps for flow detection
    submission_times: Vec<(u64, Instant)>, // (signature, time)
}

/// State for tracking an active multi-step flow
#[derive(Debug)]
struct ActiveFlowState {
    /// Start URL of the flow
    start_url: String,

    /// Submissions in the current flow
    submissions: Vec<FormSubmission>,

    /// When the flow started
    started_at: Instant,

    /// Last submission time
    last_submission_at: Instant,

    /// Expected next URL patterns
    expected_patterns: Vec<String>,
}

impl FormRecorder {
    /// Create a new form recorder with default configuration
    pub fn new() -> Self {
        Self::with_config(FormRecorderConfig::default())
    }

    /// Create a new form recorder with custom configuration
    pub fn with_config(config: FormRecorderConfig) -> Self {
        Self {
            config,
            submissions: Vec::new(),
            sequences: Vec::new(),
            seen_signatures: HashSet::new(),
            active_flow: None,
            current_state: SequenceState::default(),
            submission_times: Vec::new(),
        }
    }

    /// Record a form submission
    ///
    /// This is called when a form is submitted during crawl. The recorder will:
    /// 1. Check for duplicates
    /// 2. Analyze fields for token detection
    /// 3. Track wizard flow progress
    pub fn record_submission(&mut self, mut submission: FormSubmission) -> bool {
        // Check limits
        if self.submissions.len() >= self.config.max_total_submissions {
            debug!("[FormRecorder] Max submissions reached, skipping");
            return false;
        }

        // Check for duplicate
        let sig = submission.signature();
        if self.seen_signatures.contains(&sig) {
            debug!(
                "[FormRecorder] Duplicate submission, skipping: {}",
                submission.action_url
            );
            return false;
        }

        // Analyze fields
        for field in &mut submission.fields {
            if Self::is_token_value(&field.value) {
                field.is_dynamic_token = true;
                if field.token_type.is_none() {
                    field.token_type = Some(TokenType::Unknown);
                }
            }
        }

        // Track for wizard detection
        if self.config.detect_wizards {
            self.update_flow_detection(&submission);
        }

        // Record
        self.seen_signatures.insert(sig);
        self.submission_times.push((sig, Instant::now()));
        self.submissions.push(submission);

        info!(
            "[FormRecorder] Recorded submission #{} to {}",
            self.submissions.len(),
            self.submissions
                .last()
                .map(|s| &s.action_url)
                .unwrap_or(&String::new())
        );

        true
    }

    /// Record a form submission from a DiscoveredForm
    pub fn record_from_discovered_form(&mut self, form: &DiscoveredForm) -> bool {
        let submission = FormSubmission::from_discovered_form(form);
        self.record_submission(submission)
    }

    /// Update the current session state (cookies, storage)
    pub fn update_state(&mut self, state: SequenceState) {
        self.current_state = state;
    }

    /// Update cookies
    pub fn update_cookies(&mut self, cookies: HashMap<String, String>) {
        self.current_state.cookies = cookies;
    }

    /// Set auth token
    pub fn set_auth_token(&mut self, token: Option<String>) {
        self.current_state.auth_token = token;
    }

    /// Check if a value looks like a dynamic token
    fn is_token_value(value: &Option<String>) -> bool {
        if let Some(v) = value {
            // Check for patterns that suggest dynamic tokens
            let len = v.len();

            // Long random-looking strings
            if len >= 32
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return true;
            }

            // Base64-encoded tokens
            if len >= 20
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                // Check for base64 padding or structure
                if v.ends_with('=') || (len % 4 == 0 && len >= 24) {
                    return true;
                }
            }

            // JWT-like tokens (three dot-separated parts)
            if v.matches('.').count() == 2 {
                return true;
            }

            // Timestamp-based tokens
            if v.parse::<i64>().is_ok() && len >= 10 {
                return true;
            }
        }

        false
    }

    /// Update wizard flow detection based on new submission
    fn update_flow_detection(&mut self, submission: &FormSubmission) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.flow_detection_window_secs);

        // Check if we should start a new flow or continue existing
        let should_continue = if let Some(ref flow) = self.active_flow {
            // Check if this submission continues the flow
            let time_since_last = now.duration_since(flow.last_submission_at);
            time_since_last <= window && self.is_flow_continuation(&flow.start_url, submission)
        } else {
            false
        };

        if should_continue {
            if let Some(ref mut flow) = self.active_flow {
                flow.submissions.push(submission.clone());
                flow.last_submission_at = now;
                debug!(
                    "[FormRecorder] Continuing wizard flow, step {}",
                    flow.submissions.len()
                );
                return;
            }
        } else if self.active_flow.is_some() {
            // Flow ended, finalize it
            self.finalize_active_flow();
        }

        // Check if this could start a new wizard flow
        if self.could_start_wizard(submission) {
            debug!(
                "[FormRecorder] Starting potential wizard flow at {}",
                submission.source_url
            );
            self.active_flow = Some(ActiveFlowState {
                start_url: submission.source_url.clone(),
                submissions: vec![submission.clone()],
                started_at: now,
                last_submission_at: now,
                expected_patterns: self.generate_expected_patterns(&submission.action_url),
            });
        }
    }

    /// Check if a submission could start a wizard flow
    fn could_start_wizard(&self, submission: &FormSubmission) -> bool {
        let url_lower = submission.action_url.to_lowercase();

        // URLs that often start wizard flows
        url_lower.contains("step")
            || url_lower.contains("wizard")
            || url_lower.contains("checkout")
            || url_lower.contains("register")
            || url_lower.contains("signup")
            || url_lower.contains("onboard")
            || submission.fields.len() <= 5 // Short forms often start wizards
    }

    /// Check if a submission continues an existing flow
    fn is_flow_continuation(&self, start_url: &str, submission: &FormSubmission) -> bool {
        // Check if on same domain
        if let (Ok(start), Ok(current)) = (
            url::Url::parse(start_url),
            url::Url::parse(&submission.source_url),
        ) {
            if start.host_str() != current.host_str() {
                return false;
            }
        }

        // Check for step indicators in URL
        let url_lower = submission.action_url.to_lowercase();
        if url_lower.contains("step")
            || url_lower.contains("next")
            || url_lower.contains("continue")
            || url_lower.contains("proceed")
        {
            return true;
        }

        // Check if source URL matches previous action URL (page navigation)
        if let Some(flow) = &self.active_flow {
            if let Some(last) = flow.submissions.last() {
                if submission.source_url.starts_with(&last.action_url) {
                    return true;
                }
                // Check for redirect pattern
                if let Some(ref resp_url) = last.response_url {
                    if submission.source_url == *resp_url {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Generate expected URL patterns for wizard continuation
    fn generate_expected_patterns(&self, action_url: &str) -> Vec<String> {
        let mut patterns = Vec::new();

        // Extract base path
        if let Ok(url) = url::Url::parse(action_url) {
            let path = url.path();

            // Look for step numbers and increment
            if let Some(idx) = path.find("step") {
                let after_step = &path[idx + 4..];
                if let Some(num) = after_step
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
                {
                    let next_step = format!("step{}", num + 1);
                    patterns.push(next_step);
                }
            }

            // Common next patterns
            patterns.push("next".to_string());
            patterns.push("continue".to_string());
            patterns.push("proceed".to_string());
        }

        patterns
    }

    /// Finalize the active flow into a sequence
    fn finalize_active_flow(&mut self) {
        if let Some(flow) = self.active_flow.take() {
            // Only create sequence if we have multiple steps
            if flow.submissions.len() >= 2 {
                let mut sequence = FormSequence::new(
                    format!("Wizard Flow #{}", self.sequences.len() + 1),
                    flow.start_url,
                );
                sequence.is_wizard = true;
                sequence.initial_state = self.current_state.clone();

                for submission in flow.submissions {
                    sequence.add_submission(submission);
                }

                if let Some(last) = sequence.submissions.last() {
                    sequence.end_url = last.response_url.clone();
                }

                sequence.detect_flow_type();

                info!(
                    "[FormRecorder] Finalized wizard sequence with {} steps: {:?}",
                    sequence.step_count, sequence.flow_type
                );

                self.sequences.push(sequence);
            }
        }
    }

    /// Finalize recording and return all collected data
    pub fn finalize(mut self) -> FormRecorderResults {
        // Finalize any active flow
        self.finalize_active_flow();

        // Group remaining submissions into single-step sequences
        let standalone_submissions: Vec<_> = self
            .submissions
            .iter()
            .filter(|s| s.sequence_index.is_none())
            .cloned()
            .collect();

        for submission in standalone_submissions {
            let mut sequence = FormSequence::new(
                format!("Form: {}", submission.action_url),
                submission.source_url.clone(),
            );
            sequence.initial_state = self.current_state.clone();
            sequence.add_submission(submission);
            sequence.detect_flow_type();
            self.sequences.push(sequence);
        }

        let wizard_count = self.sequences.iter().filter(|s| s.is_wizard).count();
        let total = self.submissions.len();

        FormRecorderResults {
            sequences: self.sequences,
            total_submissions: total,
            wizard_flows_detected: wizard_count,
        }
    }

    /// Get current recording statistics
    pub fn stats(&self) -> FormRecorderStats {
        FormRecorderStats {
            total_submissions: self.submissions.len(),
            unique_forms: self.seen_signatures.len(),
            active_flow_steps: self
                .active_flow
                .as_ref()
                .map(|f| f.submissions.len())
                .unwrap_or(0),
            sequences_detected: self.sequences.len(),
        }
    }
}

impl Default for FormRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// Results from form recording
#[derive(Debug, Clone)]
pub struct FormRecorderResults {
    /// All detected form sequences
    pub sequences: Vec<FormSequence>,

    /// Total number of submissions recorded
    pub total_submissions: usize,

    /// Number of wizard flows detected
    pub wizard_flows_detected: usize,
}

/// Recording statistics
#[derive(Debug, Clone)]
pub struct FormRecorderStats {
    /// Total submissions recorded
    pub total_submissions: usize,

    /// Unique forms seen
    pub unique_forms: usize,

    /// Steps in currently active flow
    pub active_flow_steps: usize,

    /// Sequences detected so far
    pub sequences_detected: usize,
}

// ============================================================================
// Form Replayer - Replays Sequences with Modifications
// ============================================================================

/// Configuration for form replay
#[derive(Debug, Clone)]
pub struct FormReplayConfig {
    /// Timeout for each form submission (seconds)
    pub submission_timeout_secs: u64,

    /// Delay between steps in a sequence (milliseconds)
    pub step_delay_ms: u64,

    /// Whether to automatically refresh CSRF tokens
    pub auto_refresh_csrf: bool,

    /// Whether to restore state before replay
    pub restore_state: bool,

    /// Maximum retries for failed submissions
    pub max_retries: u32,

    /// Auth token for authenticated replays
    pub auth_token: Option<String>,

    /// Custom HTTP headers to inject into all requests (Authorization, Cookie, etc.)
    pub custom_headers: HashMap<String, String>,
}

impl Default for FormReplayConfig {
    fn default() -> Self {
        Self {
            submission_timeout_secs: 30,
            step_delay_ms: 500,
            auto_refresh_csrf: true,
            restore_state: true,
            max_retries: 2,
            auth_token: None,
            custom_headers: HashMap::new(),
        }
    }
}

/// Replays recorded form sequences with modifications for security testing
pub struct FormReplayer {
    /// Configuration
    config: FormReplayConfig,

    /// Headless crawler for browser-based replay
    crawler: HeadlessCrawler,
}

/// Result of a single form submission during replay
#[derive(Debug, Clone)]
pub struct ReplaySubmissionResult {
    /// The submission that was replayed
    pub submission: FormSubmission,

    /// Whether the submission succeeded
    pub success: bool,

    /// Response URL after submission
    pub response_url: String,

    /// Response status code
    pub status_code: Option<u16>,

    /// Whether errors were detected on the page
    pub has_errors: bool,

    /// Response body excerpt (for vulnerability detection)
    pub response_excerpt: Option<String>,

    /// Time taken for this submission
    pub duration_ms: u64,

    /// Any modifications made (injected payloads)
    pub modifications: Vec<FieldModification>,
}

/// A field modification made during replay
#[derive(Debug, Clone)]
pub struct FieldModification {
    /// Field name
    pub field_name: String,

    /// Original value
    pub original_value: Option<String>,

    /// Injected value
    pub injected_value: String,
}

/// Result of replaying a complete sequence
#[derive(Debug, Clone)]
pub struct ReplaySequenceResult {
    /// The sequence that was replayed
    pub sequence_id: String,

    /// Results for each submission in order
    pub submission_results: Vec<ReplaySubmissionResult>,

    /// Whether the entire sequence completed successfully
    pub sequence_success: bool,

    /// Total time for the sequence
    pub total_duration_ms: u64,

    /// Any CSRF tokens that were refreshed
    pub refreshed_tokens: Vec<String>,

    /// Errors encountered during replay
    pub errors: Vec<String>,
}

impl FormReplayer {
    /// Create a new form replayer with default configuration
    pub fn new() -> Self {
        Self::with_config(FormReplayConfig::default())
    }

    /// Create a new form replayer with custom configuration
    pub fn with_config(config: FormReplayConfig) -> Self {
        let crawler = HeadlessCrawler::with_headers(
            config.submission_timeout_secs,
            config.auth_token.clone(),
            config.custom_headers.clone(),
        );

        Self { config, crawler }
    }

    /// Replay a sequence exactly as recorded (baseline test)
    pub async fn replay_baseline(&self, sequence: &FormSequence) -> Result<ReplaySequenceResult> {
        info!(
            "[FormReplayer] Starting baseline replay of sequence: {}",
            sequence.name
        );
        self.replay_sequence_internal(sequence, vec![]).await
    }

    /// Replay a sequence with a single field injection
    pub async fn replay_with_injection(
        &self,
        sequence: &FormSequence,
        field_name: &str,
        payload: &str,
    ) -> Result<ReplaySequenceResult> {
        info!(
            "[FormReplayer] Replaying with injection: {} = {}",
            field_name, payload
        );

        let modification = FieldModification {
            field_name: field_name.to_string(),
            original_value: None, // Will be filled during replay
            injected_value: payload.to_string(),
        };

        self.replay_sequence_internal(sequence, vec![modification])
            .await
    }

    /// Replay with multiple field injections
    pub async fn replay_with_modifications(
        &self,
        sequence: &FormSequence,
        modifications: Vec<FieldModification>,
    ) -> Result<ReplaySequenceResult> {
        info!(
            "[FormReplayer] Replaying with {} modifications",
            modifications.len()
        );
        self.replay_sequence_internal(sequence, modifications).await
    }

    /// Internal replay implementation
    async fn replay_sequence_internal(
        &self,
        sequence: &FormSequence,
        modifications: Vec<FieldModification>,
    ) -> Result<ReplaySequenceResult> {
        let start_time = Instant::now();
        let mut submission_results = Vec::new();
        let mut refreshed_tokens = Vec::new();
        let mut errors = Vec::new();
        let mut sequence_success = true;

        // Restore state if configured
        if self.config.restore_state {
            self.restore_state(&sequence.initial_state).await?;
        }

        // Navigate to start URL
        debug!(
            "[FormReplayer] Navigating to start URL: {}",
            sequence.start_url
        );

        // Process each submission in order
        for (idx, submission) in sequence.submissions.iter().enumerate() {
            info!(
                "[FormReplayer] Processing step {}/{}: {}",
                idx + 1,
                sequence.submissions.len(),
                submission.action_url
            );

            // Refresh CSRF token if needed
            if self.config.auto_refresh_csrf
                && submission
                    .fields
                    .iter()
                    .any(|f| f.token_type == Some(TokenType::Csrf))
            {
                if let Some(csrf) = self.refresh_csrf_for_submission(submission).await? {
                    refreshed_tokens.push(csrf.field_name.clone());
                }
            }

            // Apply modifications
            let modified_submission = self.apply_modifications(submission, &modifications);

            // Submit the form
            let submit_start = Instant::now();
            let result = self.submit_form(&modified_submission).await;

            let duration_ms = submit_start.elapsed().as_millis() as u64;

            match result {
                Ok(submit_result) => {
                    let has_errors = submit_result.has_error;

                    submission_results.push(ReplaySubmissionResult {
                        submission: modified_submission.clone(),
                        success: submit_result.success,
                        response_url: submit_result.final_url,
                        status_code: None, // Would need to capture from browser
                        has_errors,
                        response_excerpt: None,
                        duration_ms,
                        modifications: modifications
                            .iter()
                            .filter(|m| {
                                modified_submission
                                    .fields
                                    .iter()
                                    .any(|f| f.name == m.field_name)
                            })
                            .cloned()
                            .collect(),
                    });

                    if !submit_result.success {
                        sequence_success = false;
                        errors.push(format!(
                            "Step {} failed: {}",
                            idx + 1,
                            submit_result.submit_status
                        ));
                    }
                }
                Err(e) => {
                    sequence_success = false;
                    errors.push(format!("Step {} error: {}", idx + 1, e));

                    submission_results.push(ReplaySubmissionResult {
                        submission: modified_submission.clone(),
                        success: false,
                        response_url: String::new(),
                        status_code: None,
                        has_errors: true,
                        response_excerpt: Some(e.to_string()),
                        duration_ms,
                        modifications: vec![],
                    });

                    // Break on error unless configured to continue
                    break;
                }
            }

            // Delay between steps
            if idx < sequence.submissions.len() - 1 {
                tokio::time::sleep(Duration::from_millis(self.config.step_delay_ms)).await;
            }
        }

        let total_duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(ReplaySequenceResult {
            sequence_id: sequence.id.clone(),
            submission_results,
            sequence_success,
            total_duration_ms,
            refreshed_tokens,
            errors,
        })
    }

    /// Restore session state before replay
    async fn restore_state(&self, state: &SequenceState) -> Result<()> {
        debug!(
            "[FormReplayer] Restoring session state: {} cookies, {} localStorage items",
            state.cookies.len(),
            state.local_storage.len()
        );

        // State restoration is handled by the crawler when navigating
        // The cookies and storage will be injected by the browser context

        Ok(())
    }

    /// Refresh CSRF token for a submission
    async fn refresh_csrf_for_submission(
        &self,
        submission: &FormSubmission,
    ) -> Result<Option<CsrfTokenInfo>> {
        // Find the CSRF field
        let csrf_field = submission
            .fields
            .iter()
            .find(|f| f.token_type == Some(TokenType::Csrf));

        if csrf_field.is_none() {
            return Ok(None);
        }

        // Extract fresh token from the source page
        let token = self
            .crawler
            .extract_csrf_token(&submission.source_url)
            .await?;

        if let Some(ref t) = token {
            debug!(
                "[FormReplayer] Refreshed CSRF token: {} = {}...",
                t.field_name,
                &t.value[..t.value.len().min(20)]
            );
        }

        Ok(token)
    }

    /// Apply modifications to a submission
    fn apply_modifications(
        &self,
        submission: &FormSubmission,
        modifications: &[FieldModification],
    ) -> FormSubmission {
        let mut modified = submission.clone();

        for modification in modifications {
            for field in &mut modified.fields {
                if field.name == modification.field_name && field.is_injectable {
                    field.value = Some(modification.injected_value.clone());
                }
            }
        }

        modified
    }

    /// Submit a form using the headless browser
    async fn submit_form(&self, submission: &FormSubmission) -> Result<FormSubmissionResult> {
        let form_data = submission.to_form_data();

        self.crawler
            .submit_form_with_csrf(&submission.source_url, &submission.action_url, &form_data)
            .await
    }

    /// Get all injectable targets from a sequence
    pub fn get_injection_targets(&self, sequence: &FormSequence) -> Vec<InjectionTarget> {
        sequence
            .submissions
            .iter()
            .enumerate()
            .flat_map(|(step_idx, submission)| {
                submission
                    .fields
                    .iter()
                    .filter(|f| f.is_injectable)
                    .map(move |field| InjectionTarget {
                        sequence_id: sequence.id.clone(),
                        step_index: step_idx,
                        field_name: field.name.clone(),
                        field_type: field.field_type.clone(),
                        current_value: field.value.clone(),
                        validation_pattern: field.validation_pattern.clone(),
                    })
            })
            .collect()
    }
}

impl Default for FormReplayer {
    fn default() -> Self {
        Self::new()
    }
}

/// An injectable target in a form sequence
#[derive(Debug, Clone)]
pub struct InjectionTarget {
    /// Sequence containing this target
    pub sequence_id: String,

    /// Step index in the sequence (0-based)
    pub step_index: usize,

    /// Field name
    pub field_name: String,

    /// Field type
    pub field_type: String,

    /// Current/recorded value
    pub current_value: Option<String>,

    /// Detected validation pattern
    pub validation_pattern: Option<String>,
}

// ============================================================================
// Integration Helpers
// ============================================================================

/// Builder for creating test sequences programmatically
#[derive(Debug)]
pub struct FormSequenceBuilder {
    sequence: FormSequence,
}

impl FormSequenceBuilder {
    /// Create a new sequence builder
    pub fn new(name: &str, start_url: &str) -> Self {
        Self {
            sequence: FormSequence::new(name.to_string(), start_url.to_string()),
        }
    }

    /// Mark as wizard flow
    pub fn wizard(mut self) -> Self {
        self.sequence.is_wizard = true;
        self
    }

    /// Set flow type
    pub fn flow_type(mut self, flow_type: FlowType) -> Self {
        self.sequence.flow_type = Some(flow_type);
        self
    }

    /// Set initial state
    pub fn with_state(mut self, state: SequenceState) -> Self {
        self.sequence.initial_state = state;
        self
    }

    /// Add a submission step
    pub fn add_step(mut self, submission: FormSubmission) -> Self {
        self.sequence.add_submission(submission);
        self
    }

    /// Build the sequence
    pub fn build(mut self) -> FormSequence {
        self.sequence.detect_flow_type();
        self.sequence
    }
}

/// Builder for creating form submissions
#[derive(Debug)]
pub struct FormSubmissionBuilder {
    submission: FormSubmission,
}

impl FormSubmissionBuilder {
    /// Create a new submission builder
    pub fn new(action_url: &str, method: &str, source_url: &str) -> Self {
        Self {
            submission: FormSubmission::new(
                action_url.to_string(),
                method.to_string(),
                source_url.to_string(),
            ),
        }
    }

    /// Add a text field
    pub fn text_field(mut self, name: &str, value: &str) -> Self {
        let mut field = FormField::new(name.to_string(), "text".to_string());
        field.value = Some(value.to_string());
        self.submission.add_field(field);
        self
    }

    /// Add an email field
    pub fn email_field(mut self, name: &str, value: &str) -> Self {
        let mut field = FormField::new(name.to_string(), "email".to_string());
        field.value = Some(value.to_string());
        field.validation_pattern = Some("email".to_string());
        self.submission.add_field(field);
        self
    }

    /// Add a password field
    pub fn password_field(mut self, name: &str, value: &str) -> Self {
        let mut field = FormField::new(name.to_string(), "password".to_string());
        field.value = Some(value.to_string());
        self.submission.add_field(field);
        self
    }

    /// Add a hidden field
    pub fn hidden_field(mut self, name: &str, value: &str) -> Self {
        let mut field = FormField::new(name.to_string(), "hidden".to_string());
        field.value = Some(value.to_string());
        field.is_injectable = false;
        self.submission.add_field(field);
        self
    }

    /// Add a CSRF token field
    pub fn csrf_field(mut self, name: &str, value: &str) -> Self {
        let mut field = FormField::new(name.to_string(), "hidden".to_string());
        field.value = Some(value.to_string());
        field.is_dynamic_token = true;
        field.token_type = Some(TokenType::Csrf);
        field.is_injectable = false;
        self.submission.add_field(field);
        self
    }

    /// Add headers
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.submission.headers = headers;
        self
    }

    /// Add cookies
    pub fn with_cookies(mut self, cookies: HashMap<String, String>) -> Self {
        self.submission.cookies = cookies;
        self
    }

    /// Build the submission
    pub fn build(self) -> FormSubmission {
        self.submission
    }
}

// ============================================================================
// Thread-Safe Recorder Wrapper
// ============================================================================

/// Thread-safe wrapper for FormRecorder for use with async crawlers
#[derive(Debug, Clone)]
pub struct SharedFormRecorder {
    inner: Arc<Mutex<FormRecorder>>,
}

impl SharedFormRecorder {
    /// Create a new shared recorder
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FormRecorder::new())),
        }
    }

    /// Create with custom config
    pub fn with_config(config: FormRecorderConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FormRecorder::with_config(config))),
        }
    }

    /// Record a submission (thread-safe)
    pub fn record_submission(&self, submission: FormSubmission) -> bool {
        if let Ok(mut recorder) = self.inner.lock() {
            recorder.record_submission(submission)
        } else {
            warn!("[SharedFormRecorder] Failed to acquire lock for recording");
            false
        }
    }

    /// Record from discovered form (thread-safe)
    pub fn record_from_discovered_form(&self, form: &DiscoveredForm) -> bool {
        if let Ok(mut recorder) = self.inner.lock() {
            recorder.record_from_discovered_form(form)
        } else {
            warn!("[SharedFormRecorder] Failed to acquire lock for recording");
            false
        }
    }

    /// Update state (thread-safe)
    pub fn update_state(&self, state: SequenceState) {
        if let Ok(mut recorder) = self.inner.lock() {
            recorder.update_state(state);
        }
    }

    /// Get stats (thread-safe)
    pub fn stats(&self) -> Option<FormRecorderStats> {
        self.inner.lock().ok().map(|r| r.stats())
    }

    /// Finalize and return results
    /// Note: This consumes the inner recorder
    pub fn finalize(self) -> Option<FormRecorderResults> {
        Arc::try_unwrap(self.inner)
            .ok()
            .and_then(|mutex| mutex.into_inner().ok())
            .map(|recorder| recorder.finalize())
    }
}

impl Default for SharedFormRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_field_token_detection() {
        // CSRF tokens
        assert!(FormField::detect_token_field("csrf_token", "hidden"));
        assert!(FormField::detect_token_field("_csrf", "hidden"));
        assert!(FormField::detect_token_field(
            "authenticity_token",
            "hidden"
        ));
        assert!(FormField::detect_token_field(
            "__RequestVerificationToken",
            "hidden"
        ));

        // Non-tokens
        assert!(!FormField::detect_token_field("email", "text"));
        assert!(!FormField::detect_token_field("username", "text"));
        assert!(!FormField::detect_token_field("password", "password"));
    }

    #[test]
    fn test_token_classification() {
        assert_eq!(FormField::classify_token("csrf_token"), TokenType::Csrf);
        assert_eq!(FormField::classify_token("xsrf-token"), TokenType::Csrf);
        assert_eq!(FormField::classify_token("nonce"), TokenType::Nonce);
        assert_eq!(FormField::classify_token("timestamp"), TokenType::Timestamp);
        assert_eq!(
            FormField::classify_token("random_field"),
            TokenType::Unknown
        );
    }

    #[test]
    fn test_form_submission_builder() {
        let submission =
            FormSubmissionBuilder::new("https://example.com/login", "POST", "https://example.com/")
                .email_field("email", "test@example.com")
                .password_field("password", "secret123")
                .csrf_field("_csrf", "abc123")
                .build();

        assert_eq!(submission.fields.len(), 3);
        assert_eq!(submission.get_injectable_fields().len(), 2); // email and password
        assert_eq!(submission.get_token_fields().len(), 1); // csrf
    }

    #[test]
    fn test_form_sequence_builder() {
        let step1 = FormSubmissionBuilder::new(
            "https://example.com/step1",
            "POST",
            "https://example.com/wizard",
        )
        .text_field("name", "John")
        .build();

        let step2 = FormSubmissionBuilder::new(
            "https://example.com/step2",
            "POST",
            "https://example.com/step1",
        )
        .email_field("email", "john@example.com")
        .build();

        let sequence = FormSequenceBuilder::new("Registration", "https://example.com/wizard")
            .wizard()
            .flow_type(FlowType::Registration)
            .add_step(step1)
            .add_step(step2)
            .build();

        assert_eq!(sequence.step_count, 2);
        assert!(sequence.is_wizard);
        assert_eq!(sequence.flow_type, Some(FlowType::Registration));
    }

    #[test]
    fn test_form_recorder() {
        let mut recorder = FormRecorder::new();

        let form = DiscoveredForm {
            action: "https://example.com/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "email".to_string(),
                input_type: "email".to_string(),
                value: Some("test@example.com".to_string()),
                options: None,
                required: true,
            }],
            discovered_at: "https://example.com/".to_string(),
        };

        assert!(recorder.record_from_discovered_form(&form));

        // Duplicate should be rejected
        assert!(!recorder.record_from_discovered_form(&form));

        let stats = recorder.stats();
        assert_eq!(stats.total_submissions, 1);
        assert_eq!(stats.unique_forms, 1);
    }

    #[test]
    fn test_is_token_value() {
        // Long random strings
        assert!(FormRecorder::is_token_value(&Some(
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6".to_string()
        )));

        // JWT-like
        assert!(FormRecorder::is_token_value(&Some(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig".to_string()
        )));

        // Base64 with padding
        assert!(FormRecorder::is_token_value(&Some(
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=".to_string()
        )));

        // Short values are not tokens
        assert!(!FormRecorder::is_token_value(&Some("hello".to_string())));
        assert!(!FormRecorder::is_token_value(&None));
    }

    #[test]
    fn test_submission_signature() {
        let sub1 = FormSubmissionBuilder::new("/submit", "POST", "/form")
            .text_field("name", "value1")
            .build();

        let sub2 = FormSubmissionBuilder::new("/submit", "POST", "/form")
            .text_field("name", "value2") // Different value
            .build();

        let sub3 = FormSubmissionBuilder::new("/submit", "POST", "/form")
            .text_field("other", "value") // Different field name
            .build();

        // Same URL, method, and field names = same signature
        assert_eq!(sub1.signature(), sub2.signature());

        // Different field names = different signature
        assert_ne!(sub1.signature(), sub3.signature());
    }

    #[test]
    fn test_injection_target_extraction() {
        let submission = FormSubmissionBuilder::new("/submit", "POST", "/form")
            .text_field("username", "test")
            .email_field("email", "test@example.com")
            .csrf_field("_csrf", "token123")
            .build();

        let sequence = FormSequenceBuilder::new("Test", "/form")
            .add_step(submission)
            .build();

        let replayer = FormReplayer::new();
        let targets = replayer.get_injection_targets(&sequence);

        // Should have 2 injectable targets (username, email) but not csrf
        assert_eq!(targets.len(), 2);
        assert!(targets.iter().any(|t| t.field_name == "username"));
        assert!(targets.iter().any(|t| t.field_name == "email"));
        assert!(!targets.iter().any(|t| t.field_name == "_csrf"));
    }

    #[test]
    fn test_flow_type_detection() {
        // Checkout flow
        let checkout_step = FormSubmissionBuilder::new(
            "https://shop.example.com/checkout/payment",
            "POST",
            "https://shop.example.com/checkout",
        )
        .text_field("card_number", "4111111111111111")
        .build();

        let mut checkout_seq =
            FormSequenceBuilder::new("Checkout", "https://shop.example.com/checkout")
                .add_step(checkout_step)
                .build();

        checkout_seq.detect_flow_type();
        assert_eq!(checkout_seq.flow_type, Some(FlowType::Checkout));

        // Registration flow
        let register_step = FormSubmissionBuilder::new(
            "https://example.com/register",
            "POST",
            "https://example.com/signup",
        )
        .email_field("email", "test@example.com")
        .password_field("password", "secret")
        .password_field("confirm_password", "secret")
        .build();

        let mut register_seq = FormSequenceBuilder::new("Register", "https://example.com/signup")
            .add_step(register_step)
            .build();

        register_seq.detect_flow_type();
        assert_eq!(register_seq.flow_type, Some(FlowType::Registration));
    }

    #[test]
    fn test_shared_recorder() {
        let recorder = SharedFormRecorder::new();

        let form = DiscoveredForm {
            action: "https://example.com/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "test".to_string(),
                input_type: "text".to_string(),
                value: None,
                options: None,
                required: false,
            }],
            discovered_at: "https://example.com/".to_string(),
        };

        // Clone for multi-threaded test
        let recorder_clone = recorder.clone();

        // Record from main thread
        assert!(recorder.record_from_discovered_form(&form));

        // Stats should be available
        let stats = recorder_clone.stats().unwrap();
        assert_eq!(stats.total_submissions, 1);
    }

    #[test]
    fn test_modification_application() {
        let submission = FormSubmissionBuilder::new("/submit", "POST", "/form")
            .text_field("name", "original")
            .email_field("email", "original@example.com")
            .csrf_field("_csrf", "token")
            .build();

        let replayer = FormReplayer::new();

        let modifications = vec![FieldModification {
            field_name: "name".to_string(),
            original_value: Some("original".to_string()),
            injected_value: "<script>alert(1)</script>".to_string(),
        }];

        let modified = replayer.apply_modifications(&submission, &modifications);

        // Name should be modified
        let name_field = modified.fields.iter().find(|f| f.name == "name").unwrap();
        assert_eq!(
            name_field.value,
            Some("<script>alert(1)</script>".to_string())
        );

        // Email should be unchanged
        let email_field = modified.fields.iter().find(|f| f.name == "email").unwrap();
        assert_eq!(email_field.value, Some("original@example.com".to_string()));

        // CSRF should be unchanged (not injectable)
        let csrf_field = modified.fields.iter().find(|f| f.name == "_csrf").unwrap();
        assert_eq!(csrf_field.value, Some("token".to_string()));
    }
}
