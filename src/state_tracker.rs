// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! State-Aware Crawling Module
//!
//! This module provides state tracking capabilities for the Lonkero security scanner.
//! It tracks application state changes across requests and detects state dependencies,
//! enabling intelligent crawling of stateful web applications.
//!
//! # Features
//!
//! - **State Capture**: Tracks cookies, localStorage, sessionStorage, URL params, form values
//! - **State Dependencies**: Detects when requests depend on state from previous requests
//! - **Dependency Graph**: Builds a graph of state dependencies between endpoints
//! - **Pattern Detection**: Identifies common state transition patterns (login, cart, wizard)
//! - **CSRF Token Tracking**: Detects tokens that need refreshing between requests
//!
//! # Example
//!
//! ```ignore
//! use lonkero_scanner::state_tracker::{StateTracker, StateTrackerConfig};
//!
//! let config = StateTrackerConfig::default();
//! let mut tracker = StateTracker::new(config);
//!
//! // Capture state before navigation
//! let before = tracker.capture_state("https://example.com/login");
//!
//! // ... perform navigation/action ...
//!
//! // Capture state after navigation
//! let after = tracker.capture_state("https://example.com/dashboard");
//!
//! // Record the transition
//! tracker.record_transition(before, after, "login_form_submit");
//!
//! // Analyze dependencies
//! let deps = tracker.get_dependencies_for("/dashboard");
//! ```
//!
//! @copyright 2026 Bountyy Oy
//! @license Proprietary

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the state tracker
#[derive(Debug, Clone)]
pub struct StateTrackerConfig {
    /// Maximum number of state snapshots to retain in history
    pub max_history_size: usize,
    /// Maximum number of transitions to track
    pub max_transitions: usize,
    /// Enable auth state detection
    pub detect_auth_state: bool,
    /// Enable cart/checkout state detection
    pub detect_cart_state: bool,
    /// Enable wizard/multi-step form detection
    pub detect_wizard_state: bool,
    /// Enable CSRF token tracking
    pub track_csrf_tokens: bool,
    /// Patterns that indicate authentication cookies
    pub auth_cookie_patterns: Vec<String>,
    /// Patterns that indicate session cookies
    pub session_cookie_patterns: Vec<String>,
    /// Patterns that indicate CSRF tokens
    pub csrf_token_patterns: Vec<String>,
}

impl Default for StateTrackerConfig {
    fn default() -> Self {
        Self {
            max_history_size: 1000,
            max_transitions: 5000,
            detect_auth_state: true,
            detect_cart_state: true,
            detect_wizard_state: true,
            track_csrf_tokens: true,
            auth_cookie_patterns: vec![
                "token".to_string(),
                "jwt".to_string(),
                "auth".to_string(),
                "session".to_string(),
                "sid".to_string(),
                "access_token".to_string(),
                "id_token".to_string(),
                "refresh_token".to_string(),
                "bearer".to_string(),
            ],
            session_cookie_patterns: vec![
                "session".to_string(),
                "sess".to_string(),
                "sid".to_string(),
                "PHPSESSID".to_string(),
                "JSESSIONID".to_string(),
                "ASP.NET_SessionId".to_string(),
                "connect.sid".to_string(),
                "_session".to_string(),
            ],
            csrf_token_patterns: vec![
                "csrf".to_string(),
                "xsrf".to_string(),
                "_token".to_string(),
                "authenticity_token".to_string(),
                "csrfmiddlewaretoken".to_string(),
                "__RequestVerificationToken".to_string(),
                "antiforgery".to_string(),
                "nonce".to_string(),
            ],
        }
    }
}

// ============================================================================
// State Snapshot
// ============================================================================

/// Captures the application state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Unique identifier for this snapshot
    pub id: String,
    /// URL where the snapshot was captured
    pub url: String,
    /// Timestamp when the snapshot was captured
    pub timestamp: u64,
    /// All cookies at this point
    pub cookies: HashMap<String, CookieValue>,
    /// localStorage values
    pub local_storage: HashMap<String, String>,
    /// sessionStorage values
    pub session_storage: HashMap<String, String>,
    /// URL query parameters
    pub url_params: HashMap<String, String>,
    /// URL hash/fragment
    pub url_hash: Option<String>,
    /// Hidden form field values (potential CSRF tokens, state tokens)
    pub hidden_fields: HashMap<String, String>,
    /// Detected auth state
    pub auth_state: AuthState,
    /// Detected application state type
    pub app_state: AppState,
    /// Content hash of the page (for detecting state-dependent content)
    pub content_hash: u64,
}

impl StateSnapshot {
    /// Create a new empty state snapshot
    pub fn new(url: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            url: url.to_string(),
            timestamp,
            cookies: HashMap::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            url_params: HashMap::new(),
            url_hash: None,
            hidden_fields: HashMap::new(),
            auth_state: AuthState::Unknown,
            app_state: AppState::Unknown,
            content_hash: 0,
        }
    }

    /// Create a snapshot with pre-populated data
    pub fn with_data(
        url: &str,
        cookies: HashMap<String, CookieValue>,
        local_storage: HashMap<String, String>,
        session_storage: HashMap<String, String>,
        url_params: HashMap<String, String>,
        url_hash: Option<String>,
        hidden_fields: HashMap<String, String>,
    ) -> Self {
        let mut snapshot = Self::new(url);
        snapshot.cookies = cookies;
        snapshot.local_storage = local_storage;
        snapshot.session_storage = session_storage;
        snapshot.url_params = url_params;
        snapshot.url_hash = url_hash;
        snapshot.hidden_fields = hidden_fields;
        snapshot
    }

    /// Generate a hash signature for state comparison
    pub fn signature(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();

        // Hash cookies (sorted for consistency)
        let mut cookie_keys: Vec<_> = self.cookies.keys().collect();
        cookie_keys.sort();
        for key in cookie_keys {
            key.hash(&mut hasher);
            if let Some(cookie) = self.cookies.get(key) {
                cookie.value.hash(&mut hasher);
            }
        }

        // Hash localStorage
        let mut storage_keys: Vec<_> = self.local_storage.keys().collect();
        storage_keys.sort();
        for key in storage_keys {
            key.hash(&mut hasher);
            if let Some(val) = self.local_storage.get(key) {
                val.hash(&mut hasher);
            }
        }

        // Hash sessionStorage
        let mut session_keys: Vec<_> = self.session_storage.keys().collect();
        session_keys.sort();
        for key in session_keys {
            key.hash(&mut hasher);
            if let Some(val) = self.session_storage.get(key) {
                val.hash(&mut hasher);
            }
        }

        hasher.finish()
    }

    /// Check if this snapshot has authentication state
    pub fn is_authenticated(&self) -> bool {
        matches!(self.auth_state, AuthState::LoggedIn { .. })
    }

    /// Get all CSRF-like tokens from this snapshot
    pub fn get_csrf_tokens(&self, patterns: &[String]) -> HashMap<String, String> {
        let mut tokens = HashMap::new();

        // Check hidden fields
        for (key, value) in &self.hidden_fields {
            let key_lower = key.to_lowercase();
            if patterns.iter().any(|p| key_lower.contains(&p.to_lowercase())) {
                tokens.insert(key.clone(), value.clone());
            }
        }

        // Check cookies
        for (key, cookie) in &self.cookies {
            let key_lower = key.to_lowercase();
            if patterns.iter().any(|p| key_lower.contains(&p.to_lowercase())) {
                tokens.insert(key.clone(), cookie.value.clone());
            }
        }

        // Check localStorage
        for (key, value) in &self.local_storage {
            let key_lower = key.to_lowercase();
            if patterns.iter().any(|p| key_lower.contains(&p.to_lowercase())) {
                tokens.insert(key.clone(), value.clone());
            }
        }

        tokens
    }

    /// Calculate the difference between this snapshot and another
    pub fn diff(&self, other: &StateSnapshot) -> StateDiff {
        let mut diff = StateDiff::default();

        // Compare cookies
        for (key, value) in &self.cookies {
            match other.cookies.get(key) {
                None => {
                    diff.removed_cookies.insert(key.clone(), value.clone());
                }
                Some(other_value) if other_value.value != value.value => {
                    diff.changed_cookies.insert(
                        key.clone(),
                        StateChange {
                            old_value: Some(value.value.clone()),
                            new_value: Some(other_value.value.clone()),
                        },
                    );
                }
                _ => {}
            }
        }
        for (key, value) in &other.cookies {
            if !self.cookies.contains_key(key) {
                diff.added_cookies.insert(key.clone(), value.clone());
            }
        }

        // Compare localStorage
        for (key, value) in &self.local_storage {
            match other.local_storage.get(key) {
                None => {
                    diff.removed_storage.insert(key.clone(), value.clone());
                }
                Some(other_value) if other_value != value => {
                    diff.changed_storage.insert(
                        key.clone(),
                        StateChange {
                            old_value: Some(value.clone()),
                            new_value: Some(other_value.clone()),
                        },
                    );
                }
                _ => {}
            }
        }
        for (key, value) in &other.local_storage {
            if !self.local_storage.contains_key(key) {
                diff.added_storage.insert(key.clone(), value.clone());
            }
        }

        // Compare sessionStorage
        for (key, value) in &self.session_storage {
            match other.session_storage.get(key) {
                None => {
                    diff.removed_session.insert(key.clone(), value.clone());
                }
                Some(other_value) if other_value != value => {
                    diff.changed_session.insert(
                        key.clone(),
                        StateChange {
                            old_value: Some(value.clone()),
                            new_value: Some(other_value.clone()),
                        },
                    );
                }
                _ => {}
            }
        }
        for (key, value) in &other.session_storage {
            if !self.session_storage.contains_key(key) {
                diff.added_session.insert(key.clone(), value.clone());
            }
        }

        // Compare hidden fields
        for (key, value) in &self.hidden_fields {
            match other.hidden_fields.get(key) {
                None => {
                    diff.removed_hidden.insert(key.clone(), value.clone());
                }
                Some(other_value) if other_value != value => {
                    diff.changed_hidden.insert(
                        key.clone(),
                        StateChange {
                            old_value: Some(value.clone()),
                            new_value: Some(other_value.clone()),
                        },
                    );
                }
                _ => {}
            }
        }
        for (key, value) in &other.hidden_fields {
            if !self.hidden_fields.contains_key(key) {
                diff.added_hidden.insert(key.clone(), value.clone());
            }
        }

        // Auth state change
        if self.auth_state != other.auth_state {
            diff.auth_state_changed = true;
            diff.old_auth_state = Some(self.auth_state.clone());
            diff.new_auth_state = Some(other.auth_state.clone());
        }

        diff
    }
}

/// Cookie value with metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CookieValue {
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<String>,
}

impl CookieValue {
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
            expires: None,
        }
    }

    pub fn with_attributes(
        value: &str,
        domain: Option<String>,
        path: Option<String>,
        secure: bool,
        http_only: bool,
        same_site: Option<String>,
    ) -> Self {
        Self {
            value: value.to_string(),
            domain,
            path,
            secure,
            http_only,
            same_site,
            expires: None,
        }
    }
}

/// Authentication state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthState {
    /// Unknown authentication state
    Unknown,
    /// User is logged out / anonymous
    LoggedOut,
    /// User is logged in
    LoggedIn {
        /// Type of authentication detected
        auth_type: AuthType,
        /// User identifier if detected
        user_id: Option<String>,
        /// Roles if detected
        roles: Vec<String>,
    },
    /// Session expired (had auth, now invalid)
    SessionExpired,
    /// Requires MFA/2FA to complete login
    RequiresMfa,
}

/// Type of authentication detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthType {
    /// Session cookie based
    SessionCookie,
    /// JWT token based
    Jwt,
    /// OAuth token based
    OAuth,
    /// Basic authentication
    Basic,
    /// API key based
    ApiKey,
    /// Unknown authentication mechanism
    Unknown,
}

/// Application state type (beyond auth)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AppState {
    /// Unknown state
    Unknown,
    /// Initial/landing state
    Initial,
    /// Shopping cart state
    Cart {
        item_count: Option<u32>,
        cart_id: Option<String>,
    },
    /// Checkout process
    Checkout {
        step: Option<u32>,
        total_steps: Option<u32>,
    },
    /// Wizard/multi-step form
    Wizard {
        current_step: u32,
        total_steps: Option<u32>,
        wizard_id: Option<String>,
    },
    /// Form submission in progress
    FormInProgress {
        form_id: Option<String>,
    },
    /// Payment processing
    Payment {
        payment_intent: Option<String>,
    },
    /// Error state
    Error {
        error_type: Option<String>,
    },
}

// ============================================================================
// State Difference
// ============================================================================

/// Represents the difference between two state snapshots
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateDiff {
    /// Cookies that were added
    pub added_cookies: HashMap<String, CookieValue>,
    /// Cookies that were removed
    pub removed_cookies: HashMap<String, CookieValue>,
    /// Cookies that changed value
    pub changed_cookies: HashMap<String, StateChange>,

    /// localStorage items added
    pub added_storage: HashMap<String, String>,
    /// localStorage items removed
    pub removed_storage: HashMap<String, String>,
    /// localStorage items changed
    pub changed_storage: HashMap<String, StateChange>,

    /// sessionStorage items added
    pub added_session: HashMap<String, String>,
    /// sessionStorage items removed
    pub removed_session: HashMap<String, String>,
    /// sessionStorage items changed
    pub changed_session: HashMap<String, StateChange>,

    /// Hidden fields added
    pub added_hidden: HashMap<String, String>,
    /// Hidden fields removed
    pub removed_hidden: HashMap<String, String>,
    /// Hidden fields changed
    pub changed_hidden: HashMap<String, StateChange>,

    /// Whether auth state changed
    pub auth_state_changed: bool,
    /// Previous auth state
    pub old_auth_state: Option<AuthState>,
    /// New auth state
    pub new_auth_state: Option<AuthState>,
}

impl StateDiff {
    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.added_cookies.is_empty()
            || !self.removed_cookies.is_empty()
            || !self.changed_cookies.is_empty()
            || !self.added_storage.is_empty()
            || !self.removed_storage.is_empty()
            || !self.changed_storage.is_empty()
            || !self.added_session.is_empty()
            || !self.removed_session.is_empty()
            || !self.changed_session.is_empty()
            || !self.added_hidden.is_empty()
            || !self.removed_hidden.is_empty()
            || !self.changed_hidden.is_empty()
            || self.auth_state_changed
    }

    /// Get total number of changes
    pub fn change_count(&self) -> usize {
        self.added_cookies.len()
            + self.removed_cookies.len()
            + self.changed_cookies.len()
            + self.added_storage.len()
            + self.removed_storage.len()
            + self.changed_storage.len()
            + self.added_session.len()
            + self.removed_session.len()
            + self.changed_session.len()
            + self.added_hidden.len()
            + self.removed_hidden.len()
            + self.changed_hidden.len()
            + if self.auth_state_changed { 1 } else { 0 }
    }

    /// Check if this diff represents a login event
    pub fn is_login_transition(&self) -> bool {
        if !self.auth_state_changed {
            return false;
        }

        match (&self.old_auth_state, &self.new_auth_state) {
            (Some(AuthState::LoggedOut), Some(AuthState::LoggedIn { .. })) => true,
            (Some(AuthState::Unknown), Some(AuthState::LoggedIn { .. })) => true,
            _ => false,
        }
    }

    /// Check if this diff represents a logout event
    pub fn is_logout_transition(&self) -> bool {
        if !self.auth_state_changed {
            return false;
        }

        match (&self.old_auth_state, &self.new_auth_state) {
            (Some(AuthState::LoggedIn { .. }), Some(AuthState::LoggedOut)) => true,
            (Some(AuthState::LoggedIn { .. }), Some(AuthState::Unknown)) => true,
            _ => false,
        }
    }
}

/// Represents a state value change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

// ============================================================================
// State Transition
// ============================================================================

/// Records a state transition from one state to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Unique identifier for this transition
    pub id: String,
    /// State before the action
    pub before_state: StateSnapshot,
    /// State after the action
    pub after_state: StateSnapshot,
    /// The action that triggered this transition
    pub trigger_action: TriggerAction,
    /// The URL where the transition started
    pub from_url: String,
    /// The URL where the transition ended
    pub to_url: String,
    /// Time taken for this transition (ms)
    pub duration_ms: u64,
    /// The state difference
    pub diff: StateDiff,
    /// Detected transition type
    pub transition_type: TransitionType,
    /// Timestamp of the transition
    pub timestamp: u64,
}

impl StateTransition {
    /// Create a new state transition
    pub fn new(
        before: StateSnapshot,
        after: StateSnapshot,
        action: TriggerAction,
        duration_ms: u64,
    ) -> Self {
        let from_url = before.url.clone();
        let to_url = after.url.clone();
        let diff = before.diff(&after);
        let transition_type = Self::detect_transition_type(&diff, &action, &from_url, &to_url);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            before_state: before,
            after_state: after,
            trigger_action: action,
            from_url,
            to_url,
            duration_ms,
            diff,
            transition_type,
            timestamp,
        }
    }

    /// Detect the type of transition based on state changes
    fn detect_transition_type(
        diff: &StateDiff,
        action: &TriggerAction,
        from_url: &str,
        to_url: &str,
    ) -> TransitionType {
        let from_lower = from_url.to_lowercase();
        let to_lower = to_url.to_lowercase();

        // Login transition
        if diff.is_login_transition() {
            return TransitionType::Login;
        }

        // Logout transition
        if diff.is_logout_transition() {
            return TransitionType::Logout;
        }

        // Cart/checkout detection
        if to_lower.contains("cart")
            || to_lower.contains("basket")
            || action
                .to_string()
                .to_lowercase()
                .contains("add")
        {
            return TransitionType::AddToCart;
        }

        if to_lower.contains("checkout") {
            return TransitionType::Checkout;
        }

        // Wizard/step detection
        if to_lower.contains("step")
            || to_lower.contains("wizard")
            || to_lower.contains("/page/")
            || from_lower.contains("step") && to_lower.contains("step")
        {
            return TransitionType::WizardStep;
        }

        // Form submission
        if matches!(action, TriggerAction::FormSubmit { .. }) {
            return TransitionType::FormSubmission;
        }

        // Navigation
        if from_url != to_url {
            return TransitionType::Navigation;
        }

        // API call
        if matches!(action, TriggerAction::ApiCall { .. }) {
            return TransitionType::ApiCall;
        }

        TransitionType::Unknown
    }

    /// Check if this transition requires state from a previous transition
    pub fn requires_prior_state(&self) -> bool {
        // Login is required if the transition involves authenticated content
        self.after_state.is_authenticated()
            && !self.before_state.is_authenticated()
    }

    /// Get the state keys that this transition produces
    pub fn produced_state_keys(&self) -> HashSet<String> {
        let mut keys = HashSet::new();

        for key in self.diff.added_cookies.keys() {
            keys.insert(format!("cookie:{}", key));
        }
        for key in self.diff.added_storage.keys() {
            keys.insert(format!("localStorage:{}", key));
        }
        for key in self.diff.added_session.keys() {
            keys.insert(format!("sessionStorage:{}", key));
        }
        for key in self.diff.added_hidden.keys() {
            keys.insert(format!("hidden:{}", key));
        }

        keys
    }

    /// Get the state keys that this transition consumes/requires
    pub fn consumed_state_keys(&self) -> HashSet<String> {
        let mut keys = HashSet::new();

        // Required cookies from before state
        for key in self.before_state.cookies.keys() {
            keys.insert(format!("cookie:{}", key));
        }

        // Required storage from before state
        for key in self.before_state.local_storage.keys() {
            keys.insert(format!("localStorage:{}", key));
        }

        for key in self.before_state.session_storage.keys() {
            keys.insert(format!("sessionStorage:{}", key));
        }

        keys
    }
}

/// The action that triggered a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerAction {
    /// Page navigation
    Navigation {
        url: String,
    },
    /// Form submission
    FormSubmit {
        form_action: String,
        method: String,
        fields: HashMap<String, String>,
    },
    /// Button/link click
    Click {
        selector: String,
        text: Option<String>,
    },
    /// API call (XHR/fetch)
    ApiCall {
        url: String,
        method: String,
        body: Option<String>,
    },
    /// JavaScript execution
    JavaScriptExec {
        script: String,
    },
    /// Page reload
    Reload,
    /// Unknown action
    Unknown,
}

impl std::fmt::Display for TriggerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriggerAction::Navigation { url } => write!(f, "Navigate to {}", url),
            TriggerAction::FormSubmit { form_action, method, .. } => {
                write!(f, "{} form to {}", method, form_action)
            }
            TriggerAction::Click { selector, text } => {
                if let Some(t) = text {
                    write!(f, "Click '{}' ({})", t, selector)
                } else {
                    write!(f, "Click {}", selector)
                }
            }
            TriggerAction::ApiCall { url, method, .. } => write!(f, "{} {}", method, url),
            TriggerAction::JavaScriptExec { .. } => write!(f, "JavaScript execution"),
            TriggerAction::Reload => write!(f, "Page reload"),
            TriggerAction::Unknown => write!(f, "Unknown action"),
        }
    }
}

/// Type of state transition detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransitionType {
    /// User login
    Login,
    /// User logout
    Logout,
    /// Session refresh/token renewal
    SessionRefresh,
    /// Add item to cart
    AddToCart,
    /// Remove from cart
    RemoveFromCart,
    /// Enter checkout flow
    Checkout,
    /// Complete payment
    Payment,
    /// Wizard/multi-step form progress
    WizardStep,
    /// Form submission
    FormSubmission,
    /// General navigation
    Navigation,
    /// API call
    ApiCall,
    /// State reset
    Reset,
    /// Unknown transition
    Unknown,
}

impl std::fmt::Display for TransitionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransitionType::Login => write!(f, "Login"),
            TransitionType::Logout => write!(f, "Logout"),
            TransitionType::SessionRefresh => write!(f, "Session Refresh"),
            TransitionType::AddToCart => write!(f, "Add to Cart"),
            TransitionType::RemoveFromCart => write!(f, "Remove from Cart"),
            TransitionType::Checkout => write!(f, "Checkout"),
            TransitionType::Payment => write!(f, "Payment"),
            TransitionType::WizardStep => write!(f, "Wizard Step"),
            TransitionType::FormSubmission => write!(f, "Form Submission"),
            TransitionType::Navigation => write!(f, "Navigation"),
            TransitionType::ApiCall => write!(f, "API Call"),
            TransitionType::Reset => write!(f, "State Reset"),
            TransitionType::Unknown => write!(f, "Unknown"),
        }
    }
}

// ============================================================================
// State Dependency Graph
// ============================================================================

/// A node in the state dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    /// Endpoint/URL this node represents
    pub endpoint: String,
    /// State keys this endpoint requires
    pub required_state: HashSet<String>,
    /// State keys this endpoint produces
    pub produced_state: HashSet<String>,
    /// Transition types that lead to this node
    pub incoming_transitions: Vec<TransitionType>,
    /// Detected auth requirement
    pub requires_auth: bool,
    /// Specific CSRF tokens required
    pub requires_csrf: HashSet<String>,
}

impl DependencyNode {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            required_state: HashSet::new(),
            produced_state: HashSet::new(),
            incoming_transitions: Vec::new(),
            requires_auth: false,
            requires_csrf: HashSet::new(),
        }
    }
}

/// Edge in the dependency graph representing a transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Source endpoint
    pub from: String,
    /// Target endpoint
    pub to: String,
    /// Type of transition
    pub transition_type: TransitionType,
    /// State keys transferred along this edge
    pub state_transfer: HashSet<String>,
    /// Number of times this transition was observed
    pub occurrence_count: u32,
}

/// Graph of state dependencies between endpoints
#[derive(Debug, Clone, Default)]
pub struct StateDependencyGraph {
    /// All nodes (endpoints) in the graph
    nodes: HashMap<String, DependencyNode>,
    /// All edges (transitions) between endpoints
    edges: Vec<DependencyEdge>,
    /// Index of edges by source endpoint
    edges_from: HashMap<String, Vec<usize>>,
    /// Index of edges by target endpoint
    edges_to: HashMap<String, Vec<usize>>,
}

impl StateDependencyGraph {
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a node in the graph
    pub fn add_node(&mut self, endpoint: &str) -> &mut DependencyNode {
        self.nodes
            .entry(endpoint.to_string())
            .or_insert_with(|| DependencyNode::new(endpoint))
    }

    /// Add a transition as an edge in the graph
    pub fn add_transition(&mut self, transition: &StateTransition) {
        let from = normalize_endpoint(&transition.from_url);
        let to = normalize_endpoint(&transition.to_url);

        // Ensure nodes exist
        self.add_node(&from);
        self.add_node(&to);

        // Update target node with required state
        if let Some(node) = self.nodes.get_mut(&to) {
            node.required_state
                .extend(transition.consumed_state_keys());
            node.produced_state
                .extend(transition.produced_state_keys());
            node.incoming_transitions
                .push(transition.transition_type);

            // Check auth requirement
            if transition.before_state.is_authenticated() {
                node.requires_auth = true;
            }

            // Track CSRF tokens
            for key in transition.consumed_state_keys() {
                if key.to_lowercase().contains("csrf")
                    || key.to_lowercase().contains("token")
                {
                    node.requires_csrf.insert(key);
                }
            }
        }

        // Check for existing edge
        let edge_idx = self.edges.iter().position(|e| {
            e.from == from && e.to == to && e.transition_type == transition.transition_type
        });

        if let Some(idx) = edge_idx {
            // Update existing edge
            self.edges[idx].occurrence_count += 1;
            self.edges[idx]
                .state_transfer
                .extend(transition.produced_state_keys());
        } else {
            // Add new edge
            let edge = DependencyEdge {
                from: from.clone(),
                to: to.clone(),
                transition_type: transition.transition_type,
                state_transfer: transition.produced_state_keys(),
                occurrence_count: 1,
            };
            let edge_idx = self.edges.len();
            self.edges.push(edge);

            // Update indices
            self.edges_from
                .entry(from.clone())
                .or_default()
                .push(edge_idx);
            self.edges_to
                .entry(to.clone())
                .or_default()
                .push(edge_idx);
        }
    }

    /// Get all dependencies for an endpoint
    pub fn get_dependencies(&self, endpoint: &str) -> Vec<&DependencyEdge> {
        let normalized = normalize_endpoint(endpoint);
        self.edges_to
            .get(&normalized)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Get all endpoints that depend on a given endpoint
    pub fn get_dependents(&self, endpoint: &str) -> Vec<&DependencyEdge> {
        let normalized = normalize_endpoint(endpoint);
        self.edges_from
            .get(&normalized)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Get the required path to reach an endpoint (for state setup)
    pub fn get_path_to(&self, endpoint: &str) -> Option<Vec<String>> {
        let normalized = normalize_endpoint(endpoint);

        // BFS to find shortest path from a root node
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        // Find root nodes (nodes with no incoming edges or login endpoints)
        for (node_endpoint, _) in &self.nodes {
            let has_incoming = self.edges_to.contains_key(node_endpoint);
            let is_login = node_endpoint.to_lowercase().contains("login");

            if !has_incoming || is_login {
                queue.push_back(node_endpoint.clone());
                visited.insert(node_endpoint.clone());
            }
        }

        // BFS
        while let Some(current) = queue.pop_front() {
            if current == normalized {
                // Reconstruct path
                let mut path = vec![normalized.clone()];
                let mut node = &normalized;
                while let Some(p) = parent.get(node) {
                    path.push(p.clone());
                    node = p;
                }
                path.reverse();
                return Some(path);
            }

            if let Some(edges) = self.edges_from.get(&current) {
                for &edge_idx in edges {
                    let next = &self.edges[edge_idx].to;
                    if !visited.contains(next) {
                        visited.insert(next.clone());
                        parent.insert(next.clone(), current.clone());
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        None
    }

    /// Get all login transition endpoints
    pub fn get_login_endpoints(&self) -> Vec<String> {
        self.edges
            .iter()
            .filter(|e| e.transition_type == TransitionType::Login)
            .map(|e| e.to.clone())
            .collect()
    }

    /// Get all checkout flow endpoints
    pub fn get_checkout_flow(&self) -> Vec<String> {
        let mut flow = Vec::new();

        // Find cart -> checkout -> payment sequence
        for edge in &self.edges {
            if edge.transition_type == TransitionType::AddToCart {
                flow.push(edge.to.clone());
            }
        }
        for edge in &self.edges {
            if edge.transition_type == TransitionType::Checkout {
                flow.push(edge.to.clone());
            }
        }
        for edge in &self.edges {
            if edge.transition_type == TransitionType::Payment {
                flow.push(edge.to.clone());
            }
        }

        flow
    }

    /// Get statistics about the graph
    pub fn stats(&self) -> GraphStats {
        let mut transition_counts: HashMap<TransitionType, u32> = HashMap::new();
        for edge in &self.edges {
            *transition_counts
                .entry(edge.transition_type)
                .or_default() += edge.occurrence_count;
        }

        let auth_required_count = self.nodes.values().filter(|n| n.requires_auth).count();
        let csrf_required_count = self
            .nodes
            .values()
            .filter(|n| !n.requires_csrf.is_empty())
            .count();

        GraphStats {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            transition_counts,
            auth_required_endpoints: auth_required_count,
            csrf_required_endpoints: csrf_required_count,
        }
    }

    /// Get a node by endpoint
    pub fn get_node(&self, endpoint: &str) -> Option<&DependencyNode> {
        let normalized = normalize_endpoint(endpoint);
        self.nodes.get(&normalized)
    }

    /// Get all nodes
    pub fn nodes(&self) -> impl Iterator<Item = &DependencyNode> {
        self.nodes.values()
    }

    /// Get all edges
    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }
}

/// Statistics about the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub transition_counts: HashMap<TransitionType, u32>,
    pub auth_required_endpoints: usize,
    pub csrf_required_endpoints: usize,
}

// ============================================================================
// State Tracker
// ============================================================================

/// Main state tracker that records and analyzes application state
pub struct StateTracker {
    /// Configuration
    config: StateTrackerConfig,
    /// History of state snapshots
    history: VecDeque<StateSnapshot>,
    /// All recorded transitions
    transitions: Vec<StateTransition>,
    /// The dependency graph
    graph: StateDependencyGraph,
    /// Current state (latest snapshot)
    current_state: Option<StateSnapshot>,
    /// CSRF tokens that need refreshing (token key -> last value)
    csrf_tokens: HashMap<String, CsrfTokenState>,
    /// State patterns detected
    detected_patterns: Vec<StatePattern>,
    /// Lock for thread-safe updates
    lock: Arc<Mutex<()>>,
}

impl Default for StateTracker {
    fn default() -> Self {
        Self::new(StateTrackerConfig::default())
    }
}

impl StateTracker {
    /// Create a new state tracker
    pub fn new(config: StateTrackerConfig) -> Self {
        Self {
            config,
            history: VecDeque::new(),
            transitions: Vec::new(),
            graph: StateDependencyGraph::new(),
            current_state: None,
            csrf_tokens: HashMap::new(),
            detected_patterns: Vec::new(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Create a state tracker with default configuration
    ///
    /// Note: Prefer using `StateTracker::default()` via the Default trait
    pub fn with_default_config() -> Self {
        Self::new(StateTrackerConfig::default())
    }

    /// Record a state snapshot
    pub fn record_snapshot(&mut self, snapshot: StateSnapshot) {
        // Detect auth state if not already set
        let mut snapshot = snapshot;
        if snapshot.auth_state == AuthState::Unknown {
            snapshot.auth_state = Self::detect_auth_state_static(&self.config, &snapshot);
        }

        // Detect app state if not already set
        if snapshot.app_state == AppState::Unknown {
            snapshot.app_state = Self::detect_app_state_static(&self.config, &snapshot);
        }

        // Update CSRF token tracking
        Self::track_csrf_tokens_static(&self.config, &mut self.csrf_tokens, &snapshot);

        // Store snapshot
        self.current_state = Some(snapshot.clone());

        // Maintain history size
        if self.history.len() >= self.config.max_history_size {
            self.history.pop_front();
        }
        self.history.push_back(snapshot);
    }

    /// Record a state transition
    pub fn record_transition(
        &mut self,
        before: StateSnapshot,
        after: StateSnapshot,
        action: TriggerAction,
        duration_ms: u64,
    ) {
        let transition = StateTransition::new(before, after, action, duration_ms);

        // Add to graph
        self.graph.add_transition(&transition);

        // Detect patterns
        Self::detect_patterns_static(&mut self.detected_patterns, &transition);

        // Store transition
        if self.transitions.len() >= self.config.max_transitions {
            self.transitions.remove(0);
        }
        self.transitions.push(transition);
    }

    /// Record a transition from the current state to a new state
    pub fn transition_to(
        &mut self,
        new_state: StateSnapshot,
        action: TriggerAction,
        duration_ms: u64,
    ) {
        if let Some(current) = self.current_state.clone() {
            self.record_transition(current, new_state.clone(), action, duration_ms);
        }
        self.record_snapshot(new_state);
    }

    /// Get the current state
    pub fn current_state(&self) -> Option<&StateSnapshot> {
        self.current_state.as_ref()
    }

    /// Get the state history
    pub fn history(&self) -> &VecDeque<StateSnapshot> {
        &self.history
    }

    /// Get all transitions
    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }

    /// Get the dependency graph
    pub fn graph(&self) -> &StateDependencyGraph {
        &self.graph
    }

    /// Get dependencies for an endpoint
    pub fn get_dependencies_for(&self, endpoint: &str) -> Vec<&DependencyEdge> {
        self.graph.get_dependencies(endpoint)
    }

    /// Get the path required to reach an endpoint
    pub fn get_path_to(&self, endpoint: &str) -> Option<Vec<String>> {
        self.graph.get_path_to(endpoint)
    }

    /// Check if an endpoint requires authentication
    pub fn requires_auth(&self, endpoint: &str) -> bool {
        self.graph
            .get_node(endpoint)
            .map(|n| n.requires_auth)
            .unwrap_or(false)
    }

    /// Get CSRF tokens that may need refreshing
    pub fn get_csrf_tokens(&self) -> &HashMap<String, CsrfTokenState> {
        &self.csrf_tokens
    }

    /// Get detected state patterns
    pub fn get_patterns(&self) -> &[StatePattern] {
        &self.detected_patterns
    }

    /// Get summary statistics
    pub fn summary(&self) -> TrackerSummary {
        TrackerSummary {
            snapshot_count: self.history.len(),
            transition_count: self.transitions.len(),
            graph_stats: self.graph.stats(),
            csrf_token_count: self.csrf_tokens.len(),
            pattern_count: self.detected_patterns.len(),
            current_auth_state: self
                .current_state
                .as_ref()
                .map(|s| s.auth_state.clone())
                .unwrap_or(AuthState::Unknown),
        }
    }

    // ========================================================================
    // Internal Detection Methods (Static versions to avoid borrow issues)
    // ========================================================================

    /// Detect authentication state from a snapshot (static version)
    fn detect_auth_state_static(config: &StateTrackerConfig, snapshot: &StateSnapshot) -> AuthState {
        if !config.detect_auth_state {
            return AuthState::Unknown;
        }

        // Check for auth cookies
        for (name, cookie) in &snapshot.cookies {
            let name_lower = name.to_lowercase();

            // Check against auth patterns
            for pattern in &config.auth_cookie_patterns {
                if name_lower.contains(&pattern.to_lowercase()) {
                    // JWT detection
                    if cookie.value.matches('.').count() == 2
                        && cookie.value.len() > 50
                    {
                        return AuthState::LoggedIn {
                            auth_type: AuthType::Jwt,
                            user_id: extract_jwt_subject(&cookie.value),
                            roles: Vec::new(),
                        };
                    }

                    // Session cookie
                    if config
                        .session_cookie_patterns
                        .iter()
                        .any(|p| name_lower.contains(&p.to_lowercase()))
                    {
                        return AuthState::LoggedIn {
                            auth_type: AuthType::SessionCookie,
                            user_id: None,
                            roles: Vec::new(),
                        };
                    }
                }
            }
        }

        // Check localStorage for tokens
        for (key, value) in &snapshot.local_storage {
            let key_lower = key.to_lowercase();
            if key_lower.contains("token")
                || key_lower.contains("auth")
                || key_lower.contains("jwt")
            {
                if value.matches('.').count() == 2 && value.len() > 50 {
                    return AuthState::LoggedIn {
                        auth_type: AuthType::Jwt,
                        user_id: extract_jwt_subject(value),
                        roles: Vec::new(),
                    };
                }
            }
        }

        // Check sessionStorage
        for (key, value) in &snapshot.session_storage {
            let key_lower = key.to_lowercase();
            if key_lower.contains("token") || key_lower.contains("auth") {
                if !value.is_empty() {
                    return AuthState::LoggedIn {
                        auth_type: AuthType::Unknown,
                        user_id: None,
                        roles: Vec::new(),
                    };
                }
            }
        }

        AuthState::Unknown
    }

    /// Detect application state from a snapshot (static version)
    fn detect_app_state_static(config: &StateTrackerConfig, snapshot: &StateSnapshot) -> AppState {
        let url_lower = snapshot.url.to_lowercase();

        // Cart detection
        if config.detect_cart_state {
            if url_lower.contains("cart") || url_lower.contains("basket") {
                return AppState::Cart {
                    item_count: None,
                    cart_id: snapshot
                        .cookies
                        .get("cart_id")
                        .map(|c| c.value.clone()),
                };
            }

            if url_lower.contains("checkout") {
                return AppState::Checkout {
                    step: extract_step_from_url(&url_lower),
                    total_steps: None,
                };
            }
        }

        // Wizard detection
        if config.detect_wizard_state {
            if let Some(step) = extract_step_from_url(&url_lower) {
                return AppState::Wizard {
                    current_step: step,
                    total_steps: None,
                    wizard_id: snapshot.url_params.get("wizard_id").cloned(),
                };
            }
        }

        AppState::Unknown
    }

    /// Track CSRF tokens for refresh detection (static version)
    fn track_csrf_tokens_static(
        config: &StateTrackerConfig,
        csrf_tokens: &mut HashMap<String, CsrfTokenState>,
        snapshot: &StateSnapshot,
    ) {
        if !config.track_csrf_tokens {
            return;
        }

        let tokens = snapshot.get_csrf_tokens(&config.csrf_token_patterns);

        for (key, value) in tokens {
            let entry = csrf_tokens.entry(key.clone()).or_insert_with(|| {
                CsrfTokenState {
                    key: key.clone(),
                    current_value: value.clone(),
                    previous_values: Vec::new(),
                    change_count: 0,
                    last_changed: snapshot.timestamp,
                }
            });

            if entry.current_value != value {
                entry.previous_values.push(entry.current_value.clone());
                entry.current_value = value;
                entry.change_count += 1;
                entry.last_changed = snapshot.timestamp;

                // Keep only last 10 values
                if entry.previous_values.len() > 10 {
                    entry.previous_values.remove(0);
                }
            }
        }
    }

    /// Detect patterns from transitions (static version)
    fn detect_patterns_static(detected_patterns: &mut Vec<StatePattern>, transition: &StateTransition) {
        // Login pattern
        if transition.transition_type == TransitionType::Login {
            detected_patterns.push(StatePattern {
                pattern_type: PatternType::LoginFlow,
                endpoints: vec![
                    transition.from_url.clone(),
                    transition.to_url.clone(),
                ],
                description: format!(
                    "Login flow detected: {} -> {}",
                    transition.from_url, transition.to_url
                ),
                confidence: 0.9,
            });
        }

        // Checkout pattern
        if transition.transition_type == TransitionType::Checkout {
            let existing = detected_patterns
                .iter_mut()
                .find(|p| p.pattern_type == PatternType::CheckoutFlow);

            if let Some(pattern) = existing {
                if !pattern.endpoints.contains(&transition.to_url) {
                    pattern.endpoints.push(transition.to_url.clone());
                }
            } else {
                detected_patterns.push(StatePattern {
                    pattern_type: PatternType::CheckoutFlow,
                    endpoints: vec![transition.to_url.clone()],
                    description: "Checkout flow detected".to_string(),
                    confidence: 0.8,
                });
            }
        }

        // Wizard pattern
        if transition.transition_type == TransitionType::WizardStep {
            let existing = detected_patterns
                .iter_mut()
                .find(|p| p.pattern_type == PatternType::WizardFlow);

            if let Some(pattern) = existing {
                if !pattern.endpoints.contains(&transition.to_url) {
                    pattern.endpoints.push(transition.to_url.clone());
                }
            } else {
                detected_patterns.push(StatePattern {
                    pattern_type: PatternType::WizardFlow,
                    endpoints: vec![
                        transition.from_url.clone(),
                        transition.to_url.clone(),
                    ],
                    description: "Multi-step wizard flow detected".to_string(),
                    confidence: 0.7,
                });
            }
        }
    }
}

/// CSRF token tracking state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfTokenState {
    /// Token key/name
    pub key: String,
    /// Current token value
    pub current_value: String,
    /// Previous values (for rotation detection)
    pub previous_values: Vec<String>,
    /// Number of times this token has changed
    pub change_count: u32,
    /// Timestamp of last change
    pub last_changed: u64,
}

impl CsrfTokenState {
    /// Check if this token rotates frequently (needs refresh before each request)
    pub fn is_rotating(&self) -> bool {
        self.change_count >= 3
    }
}

/// Detected state pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePattern {
    /// Type of pattern
    pub pattern_type: PatternType,
    /// Endpoints involved in this pattern
    pub endpoints: Vec<String>,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

/// Types of state patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    /// Login flow pattern
    LoginFlow,
    /// Logout flow pattern
    LogoutFlow,
    /// Shopping cart flow
    CartFlow,
    /// Checkout flow
    CheckoutFlow,
    /// Multi-step wizard
    WizardFlow,
    /// Password reset flow
    PasswordResetFlow,
    /// Registration flow
    RegistrationFlow,
    /// OAuth flow
    OAuthFlow,
    /// MFA verification flow
    MfaFlow,
}

/// Summary of tracker state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerSummary {
    pub snapshot_count: usize,
    pub transition_count: usize,
    pub graph_stats: GraphStats,
    pub csrf_token_count: usize,
    pub pattern_count: usize,
    pub current_auth_state: AuthState,
}

// ============================================================================
// State Tracking Results (for integration with SiteCrawlResults)
// ============================================================================

/// State tracking results to be included in SiteCrawlResults
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateTrackingResults {
    /// Summary statistics
    pub summary: Option<TrackerSummary>,
    /// All recorded transitions (limited for serialization)
    pub transitions: Vec<StateTransition>,
    /// Detected patterns
    pub patterns: Vec<StatePattern>,
    /// CSRF tokens that need tracking
    pub csrf_tokens: Vec<CsrfTokenState>,
    /// Endpoints requiring authentication
    pub auth_required_endpoints: Vec<String>,
    /// Login flow endpoints
    pub login_endpoints: Vec<String>,
    /// Checkout flow endpoints
    pub checkout_endpoints: Vec<String>,
    /// Dependencies between endpoints (serializable format)
    pub dependencies: Vec<EndpointDependency>,
}

/// Serializable endpoint dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDependency {
    /// The endpoint
    pub endpoint: String,
    /// Endpoints this depends on
    pub depends_on: Vec<String>,
    /// State keys required
    pub required_state: Vec<String>,
    /// Whether auth is required
    pub requires_auth: bool,
}

impl StateTracker {
    /// Export tracking results for integration with crawl results
    pub fn export_results(&self) -> StateTrackingResults {
        let mut results = StateTrackingResults {
            summary: Some(self.summary()),
            transitions: self.transitions.iter().take(100).cloned().collect(),
            patterns: self.detected_patterns.clone(),
            csrf_tokens: self.csrf_tokens.values().cloned().collect(),
            auth_required_endpoints: Vec::new(),
            login_endpoints: self.graph.get_login_endpoints(),
            checkout_endpoints: self.graph.get_checkout_flow(),
            dependencies: Vec::new(),
        };

        // Export auth-required endpoints
        for node in self.graph.nodes() {
            if node.requires_auth {
                results.auth_required_endpoints.push(node.endpoint.clone());
            }

            // Export dependencies
            let deps = self.graph.get_dependencies(&node.endpoint);
            if !deps.is_empty() || node.requires_auth || !node.required_state.is_empty() {
                results.dependencies.push(EndpointDependency {
                    endpoint: node.endpoint.clone(),
                    depends_on: deps.iter().map(|d| d.from.clone()).collect(),
                    required_state: node.required_state.iter().cloned().collect(),
                    requires_auth: node.requires_auth,
                });
            }
        }

        results
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Normalize an endpoint URL for comparison
fn normalize_endpoint(url: &str) -> String {
    // Remove query string and hash
    let without_query = url.split('?').next().unwrap_or(url);
    let without_hash = without_query.split('#').next().unwrap_or(without_query);

    // Remove trailing slash
    let trimmed = without_hash.trim_end_matches('/');

    // Return just the path if it's a full URL
    if let Ok(parsed) = url::Url::parse(trimmed) {
        parsed.path().to_string()
    } else {
        trimmed.to_string()
    }
}

/// Extract subject claim from JWT token
fn extract_jwt_subject(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode payload (middle part)
    if let Ok(decoded) = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    ) {
        if let Ok(json_str) = String::from_utf8(decoded) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                return json
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    None
}

/// Extract step number from URL
fn extract_step_from_url(url: &str) -> Option<u32> {
    // Check for /step/N or step=N patterns
    let step_regex = regex::Regex::new(r"(?:step[=/]?)(\d+)").ok()?;

    if let Some(caps) = step_regex.captures(url) {
        if let Some(m) = caps.get(1) {
            return m.as_str().parse().ok();
        }
    }

    // Check for /page/N pattern
    let page_regex = regex::Regex::new(r"/page/(\d+)").ok()?;
    if let Some(caps) = page_regex.captures(url) {
        if let Some(m) = caps.get(1) {
            return m.as_str().parse().ok();
        }
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_snapshot_creation() {
        let snapshot = StateSnapshot::new("https://example.com/test");
        assert_eq!(snapshot.url, "https://example.com/test");
        assert!(snapshot.cookies.is_empty());
        assert!(snapshot.local_storage.is_empty());
        assert!(!snapshot.id.is_empty());
    }

    #[test]
    fn test_state_snapshot_signature() {
        let mut snapshot1 = StateSnapshot::new("https://example.com/test");
        snapshot1
            .cookies
            .insert("session".to_string(), CookieValue::new("abc123"));

        let mut snapshot2 = StateSnapshot::new("https://example.com/test");
        snapshot2
            .cookies
            .insert("session".to_string(), CookieValue::new("abc123"));

        let mut snapshot3 = StateSnapshot::new("https://example.com/test");
        snapshot3
            .cookies
            .insert("session".to_string(), CookieValue::new("xyz789"));

        // Same state should have same signature
        assert_eq!(snapshot1.signature(), snapshot2.signature());

        // Different state should have different signature
        assert_ne!(snapshot1.signature(), snapshot3.signature());
    }

    #[test]
    fn test_state_diff() {
        let mut before = StateSnapshot::new("https://example.com/login");
        before
            .cookies
            .insert("visitor".to_string(), CookieValue::new("guest"));

        let mut after = StateSnapshot::new("https://example.com/dashboard");
        after
            .cookies
            .insert("session".to_string(), CookieValue::new("authenticated"));
        after
            .cookies
            .insert("visitor".to_string(), CookieValue::new("user123"));

        let diff = before.diff(&after);

        assert!(diff.has_changes());
        assert_eq!(diff.added_cookies.len(), 1);
        assert!(diff.added_cookies.contains_key("session"));
        assert_eq!(diff.changed_cookies.len(), 1);
        assert!(diff.changed_cookies.contains_key("visitor"));
    }

    #[test]
    fn test_state_transition() {
        let before = StateSnapshot::new("https://example.com/login");
        let mut after = StateSnapshot::new("https://example.com/dashboard");
        after.auth_state = AuthState::LoggedIn {
            auth_type: AuthType::SessionCookie,
            user_id: Some("user123".to_string()),
            roles: vec!["user".to_string()],
        };

        let action = TriggerAction::FormSubmit {
            form_action: "/login".to_string(),
            method: "POST".to_string(),
            fields: HashMap::new(),
        };

        let transition = StateTransition::new(before, after, action, 500);

        assert_eq!(transition.transition_type, TransitionType::Login);
        assert!(!transition.from_url.is_empty());
        assert!(!transition.to_url.is_empty());
    }

    #[test]
    fn test_state_dependency_graph() {
        let mut graph = StateDependencyGraph::new();

        let before = StateSnapshot::new("https://example.com/login");
        let mut after = StateSnapshot::new("https://example.com/dashboard");
        after.auth_state = AuthState::LoggedIn {
            auth_type: AuthType::SessionCookie,
            user_id: None,
            roles: Vec::new(),
        };

        let action = TriggerAction::FormSubmit {
            form_action: "/login".to_string(),
            method: "POST".to_string(),
            fields: HashMap::new(),
        };

        let transition = StateTransition::new(before, after, action, 500);
        graph.add_transition(&transition);

        let stats = graph.stats();
        assert_eq!(stats.node_count, 2);
        assert_eq!(stats.edge_count, 1);
    }

    #[test]
    fn test_state_tracker() {
        let mut tracker = StateTracker::default();

        // Record initial state
        let initial = StateSnapshot::new("https://example.com/login");
        tracker.record_snapshot(initial.clone());

        // Record transition to authenticated state
        let mut authenticated = StateSnapshot::new("https://example.com/dashboard");
        authenticated.auth_state = AuthState::LoggedIn {
            auth_type: AuthType::Jwt,
            user_id: Some("user@example.com".to_string()),
            roles: vec!["user".to_string()],
        };

        let action = TriggerAction::FormSubmit {
            form_action: "/api/login".to_string(),
            method: "POST".to_string(),
            fields: {
                let mut f = HashMap::new();
                f.insert("username".to_string(), "user@example.com".to_string());
                f.insert("password".to_string(), "****".to_string());
                f
            },
        };

        tracker.transition_to(authenticated, action, 1000);

        let summary = tracker.summary();
        assert_eq!(summary.snapshot_count, 2);
        assert_eq!(summary.transition_count, 1);
    }

    #[test]
    fn test_csrf_token_detection() {
        let config = StateTrackerConfig::default();
        let mut tracker = StateTracker::new(config);

        let mut snapshot = StateSnapshot::new("https://example.com/form");
        snapshot.hidden_fields.insert(
            "csrf_token".to_string(),
            "abc123xyz".to_string(),
        );

        tracker.record_snapshot(snapshot.clone());

        assert!(!tracker.get_csrf_tokens().is_empty());
        assert!(tracker.get_csrf_tokens().contains_key("csrf_token"));
    }

    #[test]
    fn test_normalize_endpoint() {
        assert_eq!(
            normalize_endpoint("https://example.com/api/users?page=1"),
            "/api/users"
        );
        assert_eq!(
            normalize_endpoint("https://example.com/api/users/"),
            "/api/users"
        );
        assert_eq!(
            normalize_endpoint("/api/users#section"),
            "/api/users"
        );
    }

    #[test]
    fn test_extract_step_from_url() {
        assert_eq!(extract_step_from_url("/checkout/step/2"), Some(2));
        assert_eq!(extract_step_from_url("/wizard?step=3"), Some(3));
        assert_eq!(extract_step_from_url("/page/5"), Some(5));
        assert_eq!(extract_step_from_url("/about"), None);
    }

    #[test]
    fn test_login_logout_detection() {
        let mut before = StateSnapshot::new("https://example.com/login");
        before.auth_state = AuthState::LoggedOut;

        let mut after = StateSnapshot::new("https://example.com/dashboard");
        after.auth_state = AuthState::LoggedIn {
            auth_type: AuthType::SessionCookie,
            user_id: None,
            roles: Vec::new(),
        };

        let diff = before.diff(&after);
        assert!(diff.is_login_transition());
        assert!(!diff.is_logout_transition());

        // Test logout
        let diff_logout = after.diff(&before);
        assert!(diff_logout.is_logout_transition());
        assert!(!diff_logout.is_login_transition());
    }

    #[test]
    fn test_pattern_detection() {
        let mut tracker = StateTracker::default();

        let before = StateSnapshot::new("https://example.com/login");
        let mut after = StateSnapshot::new("https://example.com/dashboard");
        after.auth_state = AuthState::LoggedIn {
            auth_type: AuthType::SessionCookie,
            user_id: None,
            roles: Vec::new(),
        };

        let action = TriggerAction::FormSubmit {
            form_action: "/login".to_string(),
            method: "POST".to_string(),
            fields: HashMap::new(),
        };

        tracker.record_transition(before, after, action, 500);

        let patterns = tracker.get_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_type == PatternType::LoginFlow));
    }

    #[test]
    fn test_export_results() {
        let mut tracker = StateTracker::default();

        let snapshot = StateSnapshot::new("https://example.com/test");
        tracker.record_snapshot(snapshot);

        let results = tracker.export_results();
        assert!(results.summary.is_some());
    }
}
