// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Attack Planner - Multi-step attack planning
//!
//! Plans and executes complex attack chains that require multiple steps.
//! Uses goal-directed search to find paths from current state to target state.
//!
//! # Features
//! - Goal-directed attack planning using BFS
//! - Attack state tracking with knowledge accumulation
//! - Prerequisite and outcome modeling for each attack step
//! - Success probability estimation for attack chains
//! - Common attack chain templates (Account Takeover, PrivEsc, Data Exfiltration)
//!
//! # Example Attack Chains
//! - Account Takeover: Enumerate users → Password reset flaw → Token prediction → Account access
//! - Privilege Escalation: IDOR on user endpoint → Find admin ID → Mass assignment → Admin access
//! - Data Exfiltration: SSRF to internal → Internal API discovery → Data access

use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info};

/// An attack goal we're trying to achieve
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttackGoal {
    /// Gain control of another user's account
    AccountTakeover,
    /// Elevate privileges from regular user to admin
    PrivilegeEscalation,
    /// Extract sensitive data from the application
    DataExfiltration,
    /// Achieve remote code execution on the server
    RemoteCodeExecution,
    /// Access internal network resources
    InternalNetworkAccess,
    /// Access sensitive data (PII, secrets, etc.)
    SensitiveDataAccess,
    /// Bypass authentication mechanisms
    AuthenticationBypass,
}

impl AttackGoal {
    /// Get all possible attack goals
    pub fn all() -> Vec<AttackGoal> {
        vec![
            AttackGoal::AccountTakeover,
            AttackGoal::PrivilegeEscalation,
            AttackGoal::DataExfiltration,
            AttackGoal::RemoteCodeExecution,
            AttackGoal::InternalNetworkAccess,
            AttackGoal::SensitiveDataAccess,
            AttackGoal::AuthenticationBypass,
        ]
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            AttackGoal::AccountTakeover => "Take over another user's account",
            AttackGoal::PrivilegeEscalation => "Escalate privileges to admin level",
            AttackGoal::DataExfiltration => "Extract sensitive data from application",
            AttackGoal::RemoteCodeExecution => "Achieve code execution on server",
            AttackGoal::InternalNetworkAccess => "Access internal network resources",
            AttackGoal::SensitiveDataAccess => "Access sensitive data (PII, secrets)",
            AttackGoal::AuthenticationBypass => "Bypass authentication mechanisms",
        }
    }
}

/// Current state of knowledge about the target
#[derive(Debug, Clone, Default)]
pub struct AttackState {
    /// Known usernames discovered
    pub known_users: HashSet<String>,
    /// Known email addresses discovered
    pub known_emails: HashSet<String>,
    /// Known API endpoints discovered
    pub known_endpoints: HashSet<String>,
    /// Knowledge about parameters
    pub known_parameters: HashMap<String, ParameterKnowledge>,
    /// Vulnerabilities discovered
    pub known_vulnerabilities: Vec<KnownVulnerability>,
    /// Authenticated sessions obtained
    pub authenticated_sessions: HashMap<String, SessionInfo>,
    /// Secrets discovered during scanning
    pub discovered_secrets: Vec<DiscoveredSecret>,
    /// Internal IPs found (e.g., via SSRF)
    pub internal_ips_found: HashSet<String>,
    /// Admin user IDs discovered
    pub admin_ids_found: HashSet<String>,
    /// Password reset tokens captured
    pub reset_tokens_found: Vec<ResetTokenInfo>,
    /// OAuth tokens captured
    pub oauth_tokens_found: Vec<OAuthTokenInfo>,
}

impl AttackState {
    /// Create a new empty attack state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if we have discovered any users
    pub fn has_users(&self) -> bool {
        !self.known_users.is_empty()
    }

    /// Check if we have discovered any emails
    pub fn has_emails(&self) -> bool {
        !self.known_emails.is_empty()
    }

    /// Check if we have any authenticated sessions
    pub fn has_any_session(&self) -> bool {
        !self.authenticated_sessions.is_empty()
    }

    /// Check if we have an admin session
    pub fn has_admin_session(&self) -> bool {
        self.authenticated_sessions
            .values()
            .any(|s| matches!(s.user_type, UserType::Admin))
    }

    /// Check if we have a specific vulnerability type
    pub fn has_vulnerability(&self, vuln_type: &str) -> bool {
        self.known_vulnerabilities.iter().any(|v| {
            v.vuln_type
                .to_lowercase()
                .contains(&vuln_type.to_lowercase())
        })
    }

    /// Check if we have an exploitable vulnerability of a type
    pub fn has_exploitable_vulnerability(&self, vuln_type: &str) -> bool {
        self.known_vulnerabilities.iter().any(|v| {
            v.vuln_type
                .to_lowercase()
                .contains(&vuln_type.to_lowercase())
                && v.exploitable
        })
    }

    /// Get vulnerabilities by type
    pub fn get_vulnerabilities(&self, vuln_type: &str) -> Vec<&KnownVulnerability> {
        self.known_vulnerabilities
            .iter()
            .filter(|v| {
                v.vuln_type
                    .to_lowercase()
                    .contains(&vuln_type.to_lowercase())
            })
            .collect()
    }

    /// Count vulnerabilities by severity
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.known_vulnerabilities
            .iter()
            .filter(|v| std::mem::discriminant(&v.severity) == std::mem::discriminant(&severity))
            .count()
    }
}

/// Information about a captured password reset token
#[derive(Debug, Clone)]
pub struct ResetTokenInfo {
    pub token: String,
    pub user_email: String,
    pub expires_at: Option<String>,
    pub predictable: bool,
}

/// Information about a captured OAuth token
#[derive(Debug, Clone)]
pub struct OAuthTokenInfo {
    pub token_type: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// Knowledge about a discovered parameter
#[derive(Debug, Clone)]
pub struct ParameterKnowledge {
    /// Parameter name
    pub name: String,
    /// Inferred type of the parameter
    pub param_type: ParameterType,
    /// Whether this parameter is injectable
    pub injectable: Option<bool>,
    /// Values we've seen for this parameter
    pub values_seen: Vec<String>,
    /// Endpoints where this parameter is used
    pub endpoints: HashSet<String>,
}

impl ParameterKnowledge {
    /// Create new parameter knowledge
    pub fn new(name: String, param_type: ParameterType) -> Self {
        Self {
            name,
            param_type,
            injectable: None,
            values_seen: Vec::new(),
            endpoints: HashSet::new(),
        }
    }
}

/// Types of parameters we can identify
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterType {
    /// User ID (numeric or UUID)
    UserId,
    /// Email address
    Email,
    /// Authentication/session token
    Token,
    /// File path or name
    File,
    /// URL or URI
    Url,
    /// Command or shell input
    Command,
    /// Password field
    Password,
    /// JSON data
    Json,
    /// Other/unknown
    Other,
}

impl ParameterType {
    /// Infer parameter type from name
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("user") && (lower.contains("id") || lower.contains("_id")) {
            ParameterType::UserId
        } else if lower.contains("email") || lower.contains("mail") {
            ParameterType::Email
        } else if lower.contains("token") || lower.contains("session") || lower.contains("jwt") {
            ParameterType::Token
        } else if lower.contains("file") || lower.contains("path") || lower.contains("document") {
            ParameterType::File
        } else if lower.contains("url") || lower.contains("uri") || lower.contains("redirect") {
            ParameterType::Url
        } else if lower.contains("cmd") || lower.contains("command") || lower.contains("exec") {
            ParameterType::Command
        } else if lower.contains("pass") || lower.contains("pwd") {
            ParameterType::Password
        } else if lower.contains("json") || lower.contains("data") {
            ParameterType::Json
        } else {
            ParameterType::Other
        }
    }
}

/// A vulnerability we've discovered and can potentially exploit
#[derive(Debug, Clone)]
pub struct KnownVulnerability {
    /// Type of vulnerability (e.g., "IDOR", "XSS", "SQLi")
    pub vuln_type: String,
    /// Affected endpoint
    pub endpoint: String,
    /// Affected parameter (if applicable)
    pub parameter: Option<String>,
    /// Severity of the vulnerability
    pub severity: Severity,
    /// Whether we can reliably exploit this
    pub exploitable: bool,
    /// Payload that triggered the vulnerability
    pub payload: Option<String>,
    /// Additional notes about exploitation
    pub notes: Option<String>,
}

impl KnownVulnerability {
    /// Create a new known vulnerability
    pub fn new(vuln_type: String, endpoint: String, severity: Severity) -> Self {
        Self {
            vuln_type,
            endpoint,
            parameter: None,
            severity,
            exploitable: false,
            payload: None,
            notes: None,
        }
    }

    /// Set the vulnerability as exploitable
    pub fn with_exploitable(mut self, exploitable: bool) -> Self {
        self.exploitable = exploitable;
        self
    }

    /// Add a parameter
    pub fn with_parameter(mut self, parameter: String) -> Self {
        self.parameter = Some(parameter);
        self
    }
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Get severity weight for probability calculations
    pub fn weight(&self) -> f32 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.3,
            Severity::Info => 0.1,
        }
    }
}

/// Information about an authenticated session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Type of user for this session
    pub user_type: UserType,
    /// Known permissions for this session
    pub permissions: HashSet<String>,
    /// Tokens associated with this session
    pub tokens: HashMap<String, String>,
    /// User identifier (if known)
    pub user_id: Option<String>,
    /// Session creation time
    pub created_at: Option<String>,
}

impl SessionInfo {
    /// Create a new anonymous session
    pub fn anonymous() -> Self {
        Self {
            user_type: UserType::Anonymous,
            permissions: HashSet::new(),
            tokens: HashMap::new(),
            user_id: None,
            created_at: None,
        }
    }

    /// Create a new regular user session
    pub fn regular_user(user_id: String) -> Self {
        Self {
            user_type: UserType::Regular,
            permissions: HashSet::new(),
            tokens: HashMap::new(),
            user_id: Some(user_id),
            created_at: None,
        }
    }

    /// Create a new admin session
    pub fn admin(user_id: String) -> Self {
        Self {
            user_type: UserType::Admin,
            permissions: HashSet::new(),
            tokens: HashMap::new(),
            user_id: Some(user_id),
            created_at: None,
        }
    }
}

/// Types of users/sessions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserType {
    /// No authentication
    Anonymous,
    /// Regular authenticated user
    Regular,
    /// Administrator
    Admin,
    /// Service account or API user
    Service,
}

/// A discovered secret
#[derive(Debug, Clone)]
pub struct DiscoveredSecret {
    /// Type of secret
    pub secret_type: SecretType,
    /// The secret value (should be redacted in logs)
    pub value: String,
    /// Where the secret was found
    pub location: String,
    /// Additional context
    pub context: Option<String>,
}

/// Types of secrets we can discover
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretType {
    /// API key
    ApiKey,
    /// Password
    Password,
    /// Token (JWT, session, etc.)
    Token,
    /// Private key
    PrivateKey,
    /// Database credential
    DatabaseCredential,
    /// AWS/Cloud credential
    CloudCredential,
    /// Other credential
    Credential,
}

/// An attack step that can be executed
#[derive(Debug, Clone)]
pub struct AttackStep {
    /// Unique identifier for this step
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this step does
    pub description: String,
    /// Type of attack step
    pub step_type: AttackStepType,
    /// What prerequisites must be met
    pub prerequisites: Vec<Prerequisite>,
    /// What outcomes this step can produce
    pub outcomes: Vec<Outcome>,
    /// Estimated probability of success (0.0 - 1.0)
    pub estimated_success: f32,
    /// Priority (higher = try first)
    pub priority: u32,
}

impl AttackStep {
    /// Create a new attack step
    pub fn new(id: &str, name: &str, step_type: AttackStepType) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            step_type,
            prerequisites: Vec::new(),
            outcomes: Vec::new(),
            estimated_success: 0.5,
            priority: 1,
        }
    }

    /// Add a description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Add prerequisites
    pub fn with_prerequisites(mut self, prereqs: Vec<Prerequisite>) -> Self {
        self.prerequisites = prereqs;
        self
    }

    /// Add outcomes
    pub fn with_outcomes(mut self, outcomes: Vec<Outcome>) -> Self {
        self.outcomes = outcomes;
        self
    }

    /// Set estimated success rate
    pub fn with_success_rate(mut self, rate: f32) -> Self {
        self.estimated_success = rate.clamp(0.0, 1.0);
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if prerequisites are met by current state
    pub fn can_execute(&self, state: &AttackState) -> bool {
        self.prerequisites.iter().all(|prereq| prereq.is_met(state))
    }
}

/// Types of attack steps
#[derive(Debug, Clone)]
pub enum AttackStepType {
    /// Enumerate information (users, endpoints, etc.)
    Enumerate { target: EnumerationTarget },
    /// Exploit a known vulnerability
    Exploit {
        vuln_type: String,
        payload: Option<String>,
    },
    /// Chain multiple vulnerabilities together
    ChainVuln { vuln_ids: Vec<String> },
    /// Brute force an authentication mechanism
    BruteForce { target: BruteForceTarget },
    /// Fuzz parameters for vulnerabilities
    Fuzz { target: FuzzTarget },
    /// Social engineering technique (for modeling, not execution)
    SocialEngineer { technique: String },
    /// Information gathering
    Recon { target: ReconTarget },
}

/// What to enumerate
#[derive(Debug, Clone)]
pub enum EnumerationTarget {
    /// Enumerate usernames
    Users,
    /// Enumerate email addresses
    Emails,
    /// Enumerate API endpoints
    Endpoints,
    /// Enumerate parameters
    Parameters,
    /// Enumerate permissions/roles
    Permissions,
    /// Enumerate internal IPs (via SSRF)
    InternalIps,
    /// Enumerate admin users
    AdminUsers,
}

/// What to brute force
#[derive(Debug, Clone)]
pub enum BruteForceTarget {
    /// Login credentials
    Login,
    /// Password reset tokens
    PasswordReset,
    /// One-time passwords
    OTP,
    /// API keys
    ApiKey,
    /// Session tokens
    SessionToken,
}

/// What to fuzz
#[derive(Debug, Clone)]
pub enum FuzzTarget {
    /// Fuzz for SQL injection
    SqlInjection,
    /// Fuzz for XSS
    Xss,
    /// Fuzz for command injection
    CommandInjection,
    /// Fuzz for SSRF
    Ssrf,
    /// Fuzz for path traversal
    PathTraversal,
    /// Fuzz for IDOR
    Idor,
}

/// Reconnaissance targets
#[derive(Debug, Clone)]
pub enum ReconTarget {
    /// Technology stack detection
    TechStack,
    /// Subdomain enumeration
    Subdomains,
    /// Port scanning
    Ports,
    /// Directory brute force
    Directories,
}

/// Prerequisites for attack steps
#[derive(Debug, Clone)]
pub enum Prerequisite {
    /// Must have a specific vulnerability type
    HasVulnerability(String),
    /// Must have an exploitable vulnerability
    HasExploitableVulnerability(String),
    /// Must have a list of users
    HasUserList,
    /// Must have a list of emails
    HasEmailList,
    /// Must have a specific type of session
    HasSession(UserType),
    /// Must have any authenticated session
    HasAnySession,
    /// Must know about a specific endpoint
    HasEndpoint(String),
    /// Must know about a specific parameter
    HasParameter(String),
    /// Must have access to internal network
    HasInternalAccess,
    /// Must have discovered secrets
    HasSecrets,
    /// Must have discovered admin IDs
    HasAdminIds,
    /// Must have captured reset tokens
    HasResetTokens,
    /// No prerequisites (always available)
    None,
}

impl Prerequisite {
    /// Check if this prerequisite is met by the current state
    pub fn is_met(&self, state: &AttackState) -> bool {
        match self {
            Prerequisite::HasVulnerability(vuln_type) => state.has_vulnerability(vuln_type),
            Prerequisite::HasExploitableVulnerability(vuln_type) => {
                state.has_exploitable_vulnerability(vuln_type)
            }
            Prerequisite::HasUserList => state.has_users(),
            Prerequisite::HasEmailList => state.has_emails(),
            Prerequisite::HasSession(user_type) => state
                .authenticated_sessions
                .values()
                .any(|s| &s.user_type == user_type),
            Prerequisite::HasAnySession => state.has_any_session(),
            Prerequisite::HasEndpoint(endpoint) => state.known_endpoints.contains(endpoint),
            Prerequisite::HasParameter(param) => state.known_parameters.contains_key(param),
            Prerequisite::HasInternalAccess => !state.internal_ips_found.is_empty(),
            Prerequisite::HasSecrets => !state.discovered_secrets.is_empty(),
            Prerequisite::HasAdminIds => !state.admin_ids_found.is_empty(),
            Prerequisite::HasResetTokens => !state.reset_tokens_found.is_empty(),
            Prerequisite::None => true,
        }
    }
}

/// Outcomes that attack steps can produce
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Gains an authenticated session
    GainsSession(UserType),
    /// Leaks user information
    LeaksUsers,
    /// Leaks email addresses
    LeaksEmails,
    /// Gains remote code execution
    GainsRce,
    /// Gains access to internal network
    GainsInternalAccess,
    /// Gains access to specific data
    GainsDataAccess(String),
    /// Discovers a vulnerability
    DiscoversVulnerability(String),
    /// Captures secrets
    CapturesSecrets,
    /// Captures reset tokens
    CapturesResetTokens,
    /// Discovers admin IDs
    DiscoversAdminIds,
    /// Discovers endpoints
    DiscoversEndpoints,
}

impl Outcome {
    /// Check if this outcome achieves a goal
    pub fn achieves_goal(&self, goal: &AttackGoal) -> bool {
        match (self, goal) {
            (Outcome::GainsSession(UserType::Admin), AttackGoal::PrivilegeEscalation) => true,
            (Outcome::GainsSession(_), AttackGoal::AccountTakeover) => true,
            (Outcome::GainsSession(_), AttackGoal::AuthenticationBypass) => true,
            (Outcome::GainsRce, AttackGoal::RemoteCodeExecution) => true,
            (Outcome::GainsInternalAccess, AttackGoal::InternalNetworkAccess) => true,
            (Outcome::GainsDataAccess(_), AttackGoal::DataExfiltration) => true,
            (Outcome::GainsDataAccess(_), AttackGoal::SensitiveDataAccess) => true,
            (Outcome::CapturesSecrets, AttackGoal::SensitiveDataAccess) => true,
            _ => false,
        }
    }

    /// Apply this outcome to the attack state
    pub fn apply(&self, state: &mut AttackState) {
        match self {
            Outcome::GainsSession(user_type) => {
                let session = match user_type {
                    UserType::Admin => SessionInfo::admin("captured".to_string()),
                    UserType::Regular => SessionInfo::regular_user("captured".to_string()),
                    UserType::Service => SessionInfo {
                        user_type: UserType::Service,
                        ..SessionInfo::regular_user("service".to_string())
                    },
                    UserType::Anonymous => SessionInfo::anonymous(),
                };
                state.authenticated_sessions.insert(
                    format!("session_{}", state.authenticated_sessions.len()),
                    session,
                );
            }
            Outcome::LeaksUsers => {
                // Placeholder - actual users would be added via StateUpdate
            }
            Outcome::LeaksEmails => {
                // Placeholder - actual emails would be added via StateUpdate
            }
            Outcome::GainsRce => {
                // Mark that we have RCE capability
                state.known_vulnerabilities.push(KnownVulnerability {
                    vuln_type: "RCE".to_string(),
                    endpoint: "system".to_string(),
                    parameter: None,
                    severity: Severity::Critical,
                    exploitable: true,
                    payload: None,
                    notes: Some("RCE achieved".to_string()),
                });
            }
            Outcome::GainsInternalAccess => {
                state
                    .internal_ips_found
                    .insert("internal_access".to_string());
            }
            Outcome::GainsDataAccess(data_type) => {
                state.discovered_secrets.push(DiscoveredSecret {
                    secret_type: SecretType::Credential,
                    value: "[REDACTED]".to_string(),
                    location: data_type.clone(),
                    context: Some("Data access achieved".to_string()),
                });
            }
            Outcome::DiscoversVulnerability(vuln_type) => {
                state.known_vulnerabilities.push(KnownVulnerability {
                    vuln_type: vuln_type.clone(),
                    endpoint: "discovered".to_string(),
                    parameter: None,
                    severity: Severity::Medium,
                    exploitable: false,
                    payload: None,
                    notes: None,
                });
            }
            Outcome::CapturesSecrets => {
                // Placeholder - actual secrets would be added via StateUpdate
            }
            Outcome::CapturesResetTokens => {
                // Placeholder - actual tokens would be added via StateUpdate
            }
            Outcome::DiscoversAdminIds => {
                // Placeholder - actual IDs would be added via StateUpdate
            }
            Outcome::DiscoversEndpoints => {
                // Placeholder - actual endpoints would be added via StateUpdate
            }
        }
    }
}

/// An attack plan consisting of ordered steps
#[derive(Debug, Clone)]
pub struct AttackPlan {
    /// The goal this plan aims to achieve
    pub goal: AttackGoal,
    /// Ordered list of steps to execute
    pub steps: Vec<AttackStep>,
    /// Estimated overall success probability
    pub estimated_success: f32,
    /// Required vulnerability types for this plan
    pub required_vulns: Vec<String>,
    /// Description of the attack chain
    pub description: String,
    /// Current step index
    pub current_step: usize,
}

impl AttackPlan {
    /// Create a new attack plan
    pub fn new(goal: AttackGoal, steps: Vec<AttackStep>) -> Self {
        let required_vulns = steps
            .iter()
            .filter_map(|step| {
                if let AttackStepType::Exploit { vuln_type, .. } = &step.step_type {
                    Some(vuln_type.clone())
                } else {
                    None
                }
            })
            .collect();

        let estimated_success = Self::calculate_chain_probability(&steps);

        Self {
            goal,
            steps,
            estimated_success,
            required_vulns,
            description: String::new(),
            current_step: 0,
        }
    }

    /// Calculate combined probability for a chain of steps
    fn calculate_chain_probability(steps: &[AttackStep]) -> f32 {
        if steps.is_empty() {
            return 0.0;
        }
        steps.iter().map(|s| s.estimated_success).product()
    }

    /// Get the next step to execute
    pub fn next_step(&self) -> Option<&AttackStep> {
        self.steps.get(self.current_step)
    }

    /// Advance to the next step
    pub fn advance(&mut self) -> bool {
        if self.current_step < self.steps.len() {
            self.current_step += 1;
            true
        } else {
            false
        }
    }

    /// Check if the plan is complete
    pub fn is_complete(&self) -> bool {
        self.current_step >= self.steps.len()
    }

    /// Get remaining steps count
    pub fn remaining_steps(&self) -> usize {
        self.steps.len().saturating_sub(self.current_step)
    }
}

/// State updates that can be applied to the attack state
#[derive(Debug, Clone)]
pub enum StateUpdate {
    /// Found a username
    UserFound(String),
    /// Found an email address
    EmailFound(String),
    /// Found an API endpoint
    EndpointFound(String),
    /// Found a vulnerability
    VulnFound(KnownVulnerability),
    /// Gained an authenticated session
    SessionGained(String, SessionInfo),
    /// Found a secret
    SecretFound(DiscoveredSecret),
    /// Found an internal IP address
    InternalIpFound(String),
    /// Found an admin user ID
    AdminIdFound(String),
    /// Captured a password reset token
    ResetTokenFound(ResetTokenInfo),
    /// Found an OAuth token
    OAuthTokenFound(OAuthTokenInfo),
    /// Found a parameter
    ParameterFound(String, ParameterKnowledge),
}

impl StateUpdate {
    /// Apply this update to an attack state
    pub fn apply(&self, state: &mut AttackState) {
        match self {
            StateUpdate::UserFound(user) => {
                state.known_users.insert(user.clone());
            }
            StateUpdate::EmailFound(email) => {
                state.known_emails.insert(email.clone());
            }
            StateUpdate::EndpointFound(endpoint) => {
                state.known_endpoints.insert(endpoint.clone());
            }
            StateUpdate::VulnFound(vuln) => {
                state.known_vulnerabilities.push(vuln.clone());
            }
            StateUpdate::SessionGained(name, session) => {
                state
                    .authenticated_sessions
                    .insert(name.clone(), session.clone());
            }
            StateUpdate::SecretFound(secret) => {
                state.discovered_secrets.push(secret.clone());
            }
            StateUpdate::InternalIpFound(ip) => {
                state.internal_ips_found.insert(ip.clone());
            }
            StateUpdate::AdminIdFound(id) => {
                state.admin_ids_found.insert(id.clone());
            }
            StateUpdate::ResetTokenFound(token) => {
                state.reset_tokens_found.push(token.clone());
            }
            StateUpdate::OAuthTokenFound(token) => {
                state.oauth_tokens_found.push(token.clone());
            }
            StateUpdate::ParameterFound(name, knowledge) => {
                state
                    .known_parameters
                    .insert(name.clone(), knowledge.clone());
            }
        }
    }
}

/// The main Attack Planner for multi-step attack planning
pub struct AttackPlanner {
    /// Current knowledge state
    state: AttackState,
    /// Available attack steps
    available_steps: Vec<AttackStep>,
    /// Steps that have been completed
    completed_steps: Vec<String>,
    /// Active attack plans
    active_plans: Vec<AttackPlan>,
    /// Maximum search depth for path finding
    max_search_depth: usize,
}

impl AttackPlanner {
    /// Create a new attack planner with default attack steps
    pub fn new() -> Self {
        let mut planner = Self {
            state: AttackState::new(),
            available_steps: Vec::new(),
            completed_steps: Vec::new(),
            active_plans: Vec::new(),
            max_search_depth: 10,
        };
        planner.initialize_default_steps();
        planner
    }

    /// Initialize default attack steps
    fn initialize_default_steps(&mut self) {
        // === Reconnaissance Steps ===
        self.available_steps.push(
            AttackStep::new(
                "recon_users",
                "Enumerate Users",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::Users,
                },
            )
            .with_description("Enumerate valid usernames via login/registration responses")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![Outcome::LeaksUsers])
            .with_success_rate(0.7)
            .with_priority(10),
        );

        self.available_steps.push(
            AttackStep::new(
                "recon_emails",
                "Enumerate Emails",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::Emails,
                },
            )
            .with_description("Enumerate valid email addresses via password reset")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![Outcome::LeaksEmails])
            .with_success_rate(0.6)
            .with_priority(9),
        );

        self.available_steps.push(
            AttackStep::new(
                "recon_endpoints",
                "Discover API Endpoints",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::Endpoints,
                },
            )
            .with_description("Discover API endpoints via crawling and fuzzing")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![Outcome::DiscoversEndpoints])
            .with_success_rate(0.8)
            .with_priority(10),
        );

        self.available_steps.push(
            AttackStep::new(
                "recon_admin_ids",
                "Discover Admin IDs",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::AdminUsers,
                },
            )
            .with_description("Enumerate admin user IDs via IDOR on user endpoints")
            .with_prerequisites(vec![Prerequisite::HasAnySession])
            .with_outcomes(vec![Outcome::DiscoversAdminIds])
            .with_success_rate(0.4)
            .with_priority(6),
        );

        // === Fuzzing Steps ===
        self.available_steps.push(
            AttackStep::new(
                "fuzz_idor",
                "Test for IDOR",
                AttackStepType::Fuzz {
                    target: FuzzTarget::Idor,
                },
            )
            .with_description("Test endpoints for Insecure Direct Object References")
            .with_prerequisites(vec![Prerequisite::HasAnySession])
            .with_outcomes(vec![Outcome::DiscoversVulnerability("IDOR".to_string())])
            .with_success_rate(0.5)
            .with_priority(8),
        );

        self.available_steps.push(
            AttackStep::new(
                "fuzz_ssrf",
                "Test for SSRF",
                AttackStepType::Fuzz {
                    target: FuzzTarget::Ssrf,
                },
            )
            .with_description("Test for Server-Side Request Forgery")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![
                Outcome::DiscoversVulnerability("SSRF".to_string()),
                Outcome::GainsInternalAccess,
            ])
            .with_success_rate(0.3)
            .with_priority(7),
        );

        self.available_steps.push(
            AttackStep::new(
                "fuzz_sqli",
                "Test for SQL Injection",
                AttackStepType::Fuzz {
                    target: FuzzTarget::SqlInjection,
                },
            )
            .with_description("Test parameters for SQL injection vulnerabilities")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![
                Outcome::DiscoversVulnerability("SQLi".to_string()),
                Outcome::GainsDataAccess("database".to_string()),
            ])
            .with_success_rate(0.2)
            .with_priority(8),
        );

        self.available_steps.push(
            AttackStep::new(
                "fuzz_cmdi",
                "Test for Command Injection",
                AttackStepType::Fuzz {
                    target: FuzzTarget::CommandInjection,
                },
            )
            .with_description("Test parameters for command injection")
            .with_prerequisites(vec![Prerequisite::None])
            .with_outcomes(vec![
                Outcome::DiscoversVulnerability("Command Injection".to_string()),
                Outcome::GainsRce,
            ])
            .with_success_rate(0.15)
            .with_priority(9),
        );

        // === Account Takeover Chain Steps ===
        self.available_steps.push(
            AttackStep::new(
                "ato_password_reset_flaw",
                "Exploit Password Reset Flaw",
                AttackStepType::Exploit {
                    vuln_type: "Password Reset".to_string(),
                    payload: None,
                },
            )
            .with_description("Exploit password reset token prediction or host header injection")
            .with_prerequisites(vec![Prerequisite::HasEmailList])
            .with_outcomes(vec![Outcome::CapturesResetTokens])
            .with_success_rate(0.4)
            .with_priority(7),
        );

        self.available_steps.push(
            AttackStep::new(
                "ato_token_prediction",
                "Predict Reset Token",
                AttackStepType::BruteForce {
                    target: BruteForceTarget::PasswordReset,
                },
            )
            .with_description("Predict or brute force password reset tokens")
            .with_prerequisites(vec![Prerequisite::HasResetTokens])
            .with_outcomes(vec![Outcome::GainsSession(UserType::Regular)])
            .with_success_rate(0.3)
            .with_priority(6),
        );

        self.available_steps.push(
            AttackStep::new(
                "ato_session_hijack",
                "Hijack Session via XSS",
                AttackStepType::Exploit {
                    vuln_type: "XSS".to_string(),
                    payload: None,
                },
            )
            .with_description("Steal session cookies via XSS vulnerability")
            .with_prerequisites(vec![Prerequisite::HasExploitableVulnerability(
                "XSS".to_string(),
            )])
            .with_outcomes(vec![Outcome::GainsSession(UserType::Regular)])
            .with_success_rate(0.6)
            .with_priority(7),
        );

        // === Privilege Escalation Chain Steps ===
        self.available_steps.push(
            AttackStep::new(
                "privesc_idor_admin",
                "Access Admin Data via IDOR",
                AttackStepType::Exploit {
                    vuln_type: "IDOR".to_string(),
                    payload: None,
                },
            )
            .with_description("Use IDOR to access admin user data and find admin ID")
            .with_prerequisites(vec![
                Prerequisite::HasExploitableVulnerability("IDOR".to_string()),
                Prerequisite::HasAnySession,
            ])
            .with_outcomes(vec![
                Outcome::DiscoversAdminIds,
                Outcome::GainsDataAccess("admin_data".to_string()),
            ])
            .with_success_rate(0.5)
            .with_priority(7),
        );

        self.available_steps.push(
            AttackStep::new(
                "privesc_mass_assignment",
                "Escalate via Mass Assignment",
                AttackStepType::Exploit {
                    vuln_type: "Mass Assignment".to_string(),
                    payload: None,
                },
            )
            .with_description("Modify role/admin flag via mass assignment vulnerability")
            .with_prerequisites(vec![Prerequisite::HasAdminIds, Prerequisite::HasAnySession])
            .with_outcomes(vec![Outcome::GainsSession(UserType::Admin)])
            .with_success_rate(0.4)
            .with_priority(8),
        );

        self.available_steps.push(
            AttackStep::new(
                "privesc_jwt_manipulation",
                "Manipulate JWT Claims",
                AttackStepType::Exploit {
                    vuln_type: "JWT".to_string(),
                    payload: None,
                },
            )
            .with_description("Modify JWT token to escalate privileges")
            .with_prerequisites(vec![
                Prerequisite::HasVulnerability("JWT".to_string()),
                Prerequisite::HasAnySession,
            ])
            .with_outcomes(vec![Outcome::GainsSession(UserType::Admin)])
            .with_success_rate(0.5)
            .with_priority(8),
        );

        // === Data Exfiltration Chain Steps ===
        self.available_steps.push(
            AttackStep::new(
                "exfil_ssrf_internal",
                "SSRF to Internal Network",
                AttackStepType::Exploit {
                    vuln_type: "SSRF".to_string(),
                    payload: None,
                },
            )
            .with_description("Use SSRF to access internal network resources")
            .with_prerequisites(vec![Prerequisite::HasExploitableVulnerability(
                "SSRF".to_string(),
            )])
            .with_outcomes(vec![Outcome::GainsInternalAccess])
            .with_success_rate(0.6)
            .with_priority(7),
        );

        self.available_steps.push(
            AttackStep::new(
                "exfil_internal_api",
                "Discover Internal APIs",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::InternalIps,
                },
            )
            .with_description("Enumerate internal APIs accessible via SSRF")
            .with_prerequisites(vec![Prerequisite::HasInternalAccess])
            .with_outcomes(vec![Outcome::DiscoversEndpoints, Outcome::CapturesSecrets])
            .with_success_rate(0.5)
            .with_priority(6),
        );

        self.available_steps.push(
            AttackStep::new(
                "exfil_cloud_metadata",
                "Access Cloud Metadata",
                AttackStepType::Exploit {
                    vuln_type: "SSRF".to_string(),
                    payload: Some("http://169.254.169.254/latest/meta-data/".to_string()),
                },
            )
            .with_description("Access cloud metadata service to steal credentials")
            .with_prerequisites(vec![Prerequisite::HasExploitableVulnerability(
                "SSRF".to_string(),
            )])
            .with_outcomes(vec![
                Outcome::CapturesSecrets,
                Outcome::GainsDataAccess("cloud_credentials".to_string()),
            ])
            .with_success_rate(0.7)
            .with_priority(9),
        );

        self.available_steps.push(
            AttackStep::new(
                "exfil_sqli_dump",
                "Extract Data via SQLi",
                AttackStepType::Exploit {
                    vuln_type: "SQLi".to_string(),
                    payload: None,
                },
            )
            .with_description("Dump database contents via SQL injection")
            .with_prerequisites(vec![Prerequisite::HasExploitableVulnerability(
                "SQL".to_string(),
            )])
            .with_outcomes(vec![
                Outcome::GainsDataAccess("database".to_string()),
                Outcome::CapturesSecrets,
            ])
            .with_success_rate(0.7)
            .with_priority(8),
        );

        // === RCE Chain Steps ===
        self.available_steps.push(
            AttackStep::new(
                "rce_file_upload",
                "Upload Malicious File",
                AttackStepType::Exploit {
                    vuln_type: "File Upload".to_string(),
                    payload: None,
                },
            )
            .with_description("Upload a web shell via file upload vulnerability")
            .with_prerequisites(vec![Prerequisite::HasVulnerability(
                "File Upload".to_string(),
            )])
            .with_outcomes(vec![Outcome::GainsRce])
            .with_success_rate(0.5)
            .with_priority(9),
        );

        self.available_steps.push(
            AttackStep::new(
                "rce_deserialization",
                "Exploit Deserialization",
                AttackStepType::Exploit {
                    vuln_type: "Deserialization".to_string(),
                    payload: None,
                },
            )
            .with_description("Achieve RCE via insecure deserialization")
            .with_prerequisites(vec![Prerequisite::HasVulnerability(
                "Deserialization".to_string(),
            )])
            .with_outcomes(vec![Outcome::GainsRce])
            .with_success_rate(0.4)
            .with_priority(9),
        );

        self.available_steps.push(
            AttackStep::new(
                "rce_template_injection",
                "Exploit Template Injection",
                AttackStepType::Exploit {
                    vuln_type: "SSTI".to_string(),
                    payload: None,
                },
            )
            .with_description("Achieve RCE via Server-Side Template Injection")
            .with_prerequisites(vec![Prerequisite::HasVulnerability("Template".to_string())])
            .with_outcomes(vec![Outcome::GainsRce])
            .with_success_rate(0.5)
            .with_priority(9),
        );
    }

    /// Update current state with new discovery
    pub fn update_state(&mut self, update: StateUpdate) {
        debug!("Applying state update: {:?}", update);
        update.apply(&mut self.state);
    }

    /// Get the current attack state
    pub fn get_state(&self) -> &AttackState {
        &self.state
    }

    /// Get mutable reference to attack state
    pub fn get_state_mut(&mut self) -> &mut AttackState {
        &mut self.state
    }

    /// Plan attack path to reach goal from current state
    pub fn plan_attack(&mut self, goal: AttackGoal) -> Option<AttackPlan> {
        info!("Planning attack for goal: {:?}", goal);

        // First, try to find a path using BFS
        if let Some(steps) = self.find_attack_path(&goal) {
            let mut plan = AttackPlan::new(goal.clone(), steps);
            plan.description = format!("Attack chain to achieve: {}", goal.description());

            info!(
                "Found attack path with {} steps, estimated success: {:.1}%",
                plan.steps.len(),
                plan.estimated_success * 100.0
            );

            self.active_plans.push(plan.clone());
            return Some(plan);
        }

        // If no path found, try generating goal-specific steps
        let generated_steps = match goal {
            AttackGoal::AccountTakeover => self.generate_account_takeover_steps(),
            AttackGoal::PrivilegeEscalation => self.generate_privesc_steps(),
            AttackGoal::DataExfiltration => self.generate_data_exfiltration_steps(),
            AttackGoal::RemoteCodeExecution => self.generate_rce_steps(),
            AttackGoal::InternalNetworkAccess => self.generate_internal_access_steps(),
            AttackGoal::SensitiveDataAccess => self.generate_sensitive_data_steps(),
            AttackGoal::AuthenticationBypass => self.generate_auth_bypass_steps(),
        };

        if !generated_steps.is_empty() {
            let mut plan = AttackPlan::new(goal.clone(), generated_steps);
            plan.description = format!("Generated attack chain for: {}", goal.description());

            info!(
                "Generated attack plan with {} steps, estimated success: {:.1}%",
                plan.steps.len(),
                plan.estimated_success * 100.0
            );

            self.active_plans.push(plan.clone());
            return Some(plan);
        }

        debug!("No attack path found for goal: {:?}", goal);
        None
    }

    /// Get next step to execute based on current state
    pub fn get_next_step(&self) -> Option<&AttackStep> {
        // First check active plans
        for plan in &self.active_plans {
            if let Some(step) = plan.next_step() {
                if step.can_execute(&self.state) && !self.completed_steps.contains(&step.id) {
                    return Some(step);
                }
            }
        }

        // Otherwise, find highest priority executable step
        self.available_steps
            .iter()
            .filter(|step| {
                step.can_execute(&self.state) && !self.completed_steps.contains(&step.id)
            })
            .max_by_key(|step| step.priority)
    }

    /// Mark step as completed and update state
    pub fn complete_step(&mut self, step_id: &str, success: bool, outcomes: Vec<Outcome>) {
        info!("Completing step: {} (success: {})", step_id, success);

        self.completed_steps.push(step_id.to_string());

        if success {
            // Apply outcomes to state
            for outcome in outcomes {
                debug!("Applying outcome: {:?}", outcome);
                outcome.apply(&mut self.state);
            }
        }

        // Advance any active plans that used this step
        for plan in &mut self.active_plans {
            if let Some(current) = plan.next_step() {
                if current.id == step_id {
                    plan.advance();
                }
            }
        }
    }

    /// Check if goal is achievable from current state
    pub fn is_goal_achievable(&self, goal: &AttackGoal) -> bool {
        // Check if any outcome directly achieves the goal
        for step in &self.available_steps {
            if step.can_execute(&self.state) {
                for outcome in &step.outcomes {
                    if outcome.achieves_goal(goal) {
                        return true;
                    }
                }
            }
        }

        // Try finding a path
        self.find_attack_path(goal).is_some()
    }

    /// Get all achievable goals from current state
    pub fn get_achievable_goals(&self) -> Vec<AttackGoal> {
        AttackGoal::all()
            .into_iter()
            .filter(|goal| self.is_goal_achievable(goal))
            .collect()
    }

    /// Generate attack steps for account takeover chain
    fn generate_account_takeover_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // Step 1: Enumerate users if not known
        if !self.state.has_users() && !self.state.has_emails() {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "recon_users")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "recon_users",
                            "Enumerate Users",
                            AttackStepType::Enumerate {
                                target: EnumerationTarget::Users,
                            },
                        )
                    }),
            );

            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "recon_emails")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "recon_emails",
                            "Enumerate Emails",
                            AttackStepType::Enumerate {
                                target: EnumerationTarget::Emails,
                            },
                        )
                    }),
            );
        }

        // Step 2: Try password reset exploitation
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "ato_password_reset_flaw")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "ato_password_reset_flaw",
                        "Exploit Password Reset",
                        AttackStepType::Exploit {
                            vuln_type: "Password Reset".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        // Step 3: Token prediction or session hijack
        if self.state.has_exploitable_vulnerability("XSS") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "ato_session_hijack")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "ato_session_hijack",
                            "Hijack Session",
                            AttackStepType::Exploit {
                                vuln_type: "XSS".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        } else {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "ato_token_prediction")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "ato_token_prediction",
                            "Predict Reset Token",
                            AttackStepType::BruteForce {
                                target: BruteForceTarget::PasswordReset,
                            },
                        )
                    }),
            );
        }

        steps
    }

    /// Generate attack steps for privilege escalation
    fn generate_privesc_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // Need a session first
        if !self.state.has_any_session() {
            // Try to get any session first
            steps.push(
                AttackStep::new(
                    "get_session",
                    "Obtain User Session",
                    AttackStepType::Recon {
                        target: ReconTarget::TechStack,
                    },
                )
                .with_outcomes(vec![Outcome::GainsSession(UserType::Regular)])
                .with_success_rate(0.5),
            );
        }

        // Step 1: Find IDOR on user endpoints
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "fuzz_idor")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "fuzz_idor",
                        "Test for IDOR",
                        AttackStepType::Fuzz {
                            target: FuzzTarget::Idor,
                        },
                    )
                }),
        );

        // Step 2: Find admin ID
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "privesc_idor_admin")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "privesc_idor_admin",
                        "Access Admin Data via IDOR",
                        AttackStepType::Exploit {
                            vuln_type: "IDOR".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        // Step 3: Mass assignment or JWT manipulation
        if self.state.has_vulnerability("JWT") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "privesc_jwt_manipulation")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "privesc_jwt_manipulation",
                            "Manipulate JWT",
                            AttackStepType::Exploit {
                                vuln_type: "JWT".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        } else {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "privesc_mass_assignment")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "privesc_mass_assignment",
                            "Mass Assignment Attack",
                            AttackStepType::Exploit {
                                vuln_type: "Mass Assignment".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        }

        steps
    }

    /// Generate attack steps for data exfiltration
    fn generate_data_exfiltration_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // Strategy 1: SSRF-based
        if !self.state.has_vulnerability("SSRF") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "fuzz_ssrf")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "fuzz_ssrf",
                            "Test for SSRF",
                            AttackStepType::Fuzz {
                                target: FuzzTarget::Ssrf,
                            },
                        )
                    }),
            );
        }

        // Access internal network
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "exfil_ssrf_internal")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "exfil_ssrf_internal",
                        "SSRF to Internal Network",
                        AttackStepType::Exploit {
                            vuln_type: "SSRF".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        // Cloud metadata access
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "exfil_cloud_metadata")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "exfil_cloud_metadata",
                        "Access Cloud Metadata",
                        AttackStepType::Exploit {
                            vuln_type: "SSRF".to_string(),
                            payload: Some("http://169.254.169.254/".to_string()),
                        },
                    )
                }),
        );

        // Strategy 2: SQLi-based (alternative)
        if self.state.has_vulnerability("SQL") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "exfil_sqli_dump")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "exfil_sqli_dump",
                            "Extract via SQLi",
                            AttackStepType::Exploit {
                                vuln_type: "SQLi".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        }

        steps
    }

    /// Generate attack steps for RCE
    fn generate_rce_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // Try command injection first
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "fuzz_cmdi")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "fuzz_cmdi",
                        "Test for Command Injection",
                        AttackStepType::Fuzz {
                            target: FuzzTarget::CommandInjection,
                        },
                    )
                }),
        );

        // File upload if available
        if self.state.has_vulnerability("File Upload") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "rce_file_upload")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "rce_file_upload",
                            "Upload Web Shell",
                            AttackStepType::Exploit {
                                vuln_type: "File Upload".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        }

        // Deserialization
        if self.state.has_vulnerability("Deserialization") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "rce_deserialization")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "rce_deserialization",
                            "Exploit Deserialization",
                            AttackStepType::Exploit {
                                vuln_type: "Deserialization".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        }

        // Template injection
        if self.state.has_vulnerability("Template") || self.state.has_vulnerability("SSTI") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "rce_template_injection")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "rce_template_injection",
                            "Exploit Template Injection",
                            AttackStepType::Exploit {
                                vuln_type: "SSTI".to_string(),
                                payload: None,
                            },
                        )
                    }),
            );
        }

        steps
    }

    /// Generate attack steps for internal network access
    fn generate_internal_access_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // SSRF is the primary vector
        if !self.state.has_vulnerability("SSRF") {
            steps.push(
                self.available_steps
                    .iter()
                    .find(|s| s.id == "fuzz_ssrf")
                    .cloned()
                    .unwrap_or_else(|| {
                        AttackStep::new(
                            "fuzz_ssrf",
                            "Test for SSRF",
                            AttackStepType::Fuzz {
                                target: FuzzTarget::Ssrf,
                            },
                        )
                    }),
            );
        }

        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "exfil_ssrf_internal")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "exfil_ssrf_internal",
                        "Access Internal Network",
                        AttackStepType::Exploit {
                            vuln_type: "SSRF".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "exfil_internal_api")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "exfil_internal_api",
                        "Enumerate Internal APIs",
                        AttackStepType::Enumerate {
                            target: EnumerationTarget::InternalIps,
                        },
                    )
                }),
        );

        steps
    }

    /// Generate attack steps for sensitive data access
    fn generate_sensitive_data_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // IDOR for direct access
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "fuzz_idor")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "fuzz_idor",
                        "Test for IDOR",
                        AttackStepType::Fuzz {
                            target: FuzzTarget::Idor,
                        },
                    )
                }),
        );

        // SQLi for database access
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "fuzz_sqli")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "fuzz_sqli",
                        "Test for SQLi",
                        AttackStepType::Fuzz {
                            target: FuzzTarget::SqlInjection,
                        },
                    )
                }),
        );

        // Path traversal
        steps.push(
            AttackStep::new(
                "fuzz_path_traversal",
                "Test for Path Traversal",
                AttackStepType::Fuzz {
                    target: FuzzTarget::PathTraversal,
                },
            )
            .with_outcomes(vec![Outcome::GainsDataAccess("files".to_string())])
            .with_success_rate(0.3),
        );

        steps
    }

    /// Generate attack steps for authentication bypass
    fn generate_auth_bypass_steps(&self) -> Vec<AttackStep> {
        let mut steps = Vec::new();

        // JWT manipulation
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "privesc_jwt_manipulation")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "privesc_jwt_manipulation",
                        "JWT Manipulation",
                        AttackStepType::Exploit {
                            vuln_type: "JWT".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        // SQL injection auth bypass
        steps.push(
            AttackStep::new(
                "auth_sqli_bypass",
                "SQL Injection Auth Bypass",
                AttackStepType::Exploit {
                    vuln_type: "SQLi".to_string(),
                    payload: Some("' OR '1'='1".to_string()),
                },
            )
            .with_outcomes(vec![Outcome::GainsSession(UserType::Regular)])
            .with_success_rate(0.3),
        );

        // Password reset
        steps.push(
            self.available_steps
                .iter()
                .find(|s| s.id == "ato_password_reset_flaw")
                .cloned()
                .unwrap_or_else(|| {
                    AttackStep::new(
                        "ato_password_reset_flaw",
                        "Password Reset Flaw",
                        AttackStepType::Exploit {
                            vuln_type: "Password Reset".to_string(),
                            payload: None,
                        },
                    )
                }),
        );

        steps
    }

    /// BFS to find path from current state to goal
    fn find_attack_path(&self, goal: &AttackGoal) -> Option<Vec<AttackStep>> {
        // Use BFS to find shortest path to goal
        let mut queue: VecDeque<(AttackState, Vec<AttackStep>)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        queue.push_back((self.state.clone(), Vec::new()));

        while let Some((current_state, path)) = queue.pop_front() {
            // Check depth limit
            if path.len() >= self.max_search_depth {
                continue;
            }

            // Try each available step
            for step in &self.available_steps {
                // Skip if already in path
                if path.iter().any(|s| s.id == step.id) {
                    continue;
                }

                // Skip if already completed
                if self.completed_steps.contains(&step.id) {
                    continue;
                }

                // Check if step can execute from current state
                if !step.can_execute(&current_state) {
                    continue;
                }

                // Create state key for visited tracking
                let state_key = format!(
                    "{}:{}:{}:{}",
                    step.id,
                    current_state.known_users.len(),
                    current_state.known_vulnerabilities.len(),
                    current_state.authenticated_sessions.len()
                );

                if visited.contains(&state_key) {
                    continue;
                }
                visited.insert(state_key);

                // Check if any outcome achieves goal
                for outcome in &step.outcomes {
                    if outcome.achieves_goal(goal) {
                        let mut final_path = path.clone();
                        final_path.push(step.clone());
                        debug!(
                            "Found path to goal {:?} with {} steps",
                            goal,
                            final_path.len()
                        );
                        return Some(final_path);
                    }
                }

                // Simulate state after this step
                let mut next_state = current_state.clone();
                for outcome in &step.outcomes {
                    outcome.apply(&mut next_state);
                }

                let mut next_path = path.clone();
                next_path.push(step.clone());
                queue.push_back((next_state, next_path));
            }
        }

        None
    }

    /// Add a custom attack step
    pub fn add_step(&mut self, step: AttackStep) {
        self.available_steps.push(step);
    }

    /// Get all active attack plans
    pub fn get_active_plans(&self) -> &[AttackPlan] {
        &self.active_plans
    }

    /// Clear completed steps (for retrying)
    pub fn reset_completed(&mut self) {
        self.completed_steps.clear();
    }

    /// Get statistics about current state
    pub fn get_stats(&self) -> PlannerStats {
        PlannerStats {
            known_users: self.state.known_users.len(),
            known_emails: self.state.known_emails.len(),
            known_endpoints: self.state.known_endpoints.len(),
            known_vulns: self.state.known_vulnerabilities.len(),
            sessions: self.state.authenticated_sessions.len(),
            secrets: self.state.discovered_secrets.len(),
            completed_steps: self.completed_steps.len(),
            active_plans: self.active_plans.len(),
            available_steps: self.available_steps.len(),
        }
    }
}

impl Default for AttackPlanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the planner state
#[derive(Debug, Clone)]
pub struct PlannerStats {
    pub known_users: usize,
    pub known_emails: usize,
    pub known_endpoints: usize,
    pub known_vulns: usize,
    pub sessions: usize,
    pub secrets: usize,
    pub completed_steps: usize,
    pub active_plans: usize,
    pub available_steps: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_planner_creation() {
        let planner = AttackPlanner::new();
        assert!(!planner.available_steps.is_empty());
        assert!(planner.completed_steps.is_empty());
    }

    #[test]
    fn test_state_update() {
        let mut planner = AttackPlanner::new();

        planner.update_state(StateUpdate::UserFound("admin".to_string()));
        planner.update_state(StateUpdate::EmailFound("admin@example.com".to_string()));

        assert!(planner.get_state().has_users());
        assert!(planner.get_state().has_emails());
        assert!(planner.get_state().known_users.contains("admin"));
    }

    #[test]
    fn test_vulnerability_tracking() {
        let mut planner = AttackPlanner::new();

        let vuln = KnownVulnerability::new(
            "SQL Injection".to_string(),
            "/api/users".to_string(),
            Severity::Critical,
        )
        .with_exploitable(true);

        planner.update_state(StateUpdate::VulnFound(vuln));

        assert!(planner.get_state().has_vulnerability("SQL"));
        assert!(planner.get_state().has_exploitable_vulnerability("SQL"));
    }

    #[test]
    fn test_prerequisite_checking() {
        let mut state = AttackState::new();

        // Initially empty
        assert!(!Prerequisite::HasUserList.is_met(&state));
        assert!(Prerequisite::None.is_met(&state));

        // Add users
        state.known_users.insert("user1".to_string());
        assert!(Prerequisite::HasUserList.is_met(&state));

        // Add session
        state.authenticated_sessions.insert(
            "sess1".to_string(),
            SessionInfo::regular_user("user1".to_string()),
        );
        assert!(Prerequisite::HasAnySession.is_met(&state));
        assert!(Prerequisite::HasSession(UserType::Regular).is_met(&state));
        assert!(!Prerequisite::HasSession(UserType::Admin).is_met(&state));
    }

    #[test]
    fn test_attack_step_execution_check() {
        let state = AttackState::new();

        // Step with no prerequisites should be executable
        let step1 = AttackStep::new(
            "recon",
            "Reconnaissance",
            AttackStepType::Enumerate {
                target: EnumerationTarget::Users,
            },
        )
        .with_prerequisites(vec![Prerequisite::None]);

        assert!(step1.can_execute(&state));

        // Step requiring session should not be executable
        let step2 = AttackStep::new(
            "exploit",
            "Exploit IDOR",
            AttackStepType::Exploit {
                vuln_type: "IDOR".to_string(),
                payload: None,
            },
        )
        .with_prerequisites(vec![Prerequisite::HasAnySession]);

        assert!(!step2.can_execute(&state));
    }

    #[test]
    fn test_outcome_goal_matching() {
        assert!(
            Outcome::GainsSession(UserType::Regular).achieves_goal(&AttackGoal::AccountTakeover)
        );
        assert!(
            Outcome::GainsSession(UserType::Admin).achieves_goal(&AttackGoal::PrivilegeEscalation)
        );
        assert!(Outcome::GainsRce.achieves_goal(&AttackGoal::RemoteCodeExecution));
        assert!(Outcome::GainsInternalAccess.achieves_goal(&AttackGoal::InternalNetworkAccess));
        assert!(
            Outcome::GainsDataAccess("db".to_string()).achieves_goal(&AttackGoal::DataExfiltration)
        );
    }

    #[test]
    fn test_plan_generation() {
        let mut planner = AttackPlanner::new();

        // Account takeover plan should be generatable
        let plan = planner.plan_attack(AttackGoal::AccountTakeover);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert!(!plan.steps.is_empty());
        assert!(plan.estimated_success > 0.0);
    }

    #[test]
    fn test_get_next_step() {
        let planner = AttackPlanner::new();

        // Should get a step that has no prerequisites
        let next = planner.get_next_step();
        assert!(next.is_some());

        let step = next.unwrap();
        assert!(step.can_execute(&planner.state));
    }

    #[test]
    fn test_complete_step() {
        let mut planner = AttackPlanner::new();

        let step_id = "recon_users";
        planner.complete_step(step_id, true, vec![Outcome::LeaksUsers]);

        assert!(planner.completed_steps.contains(&step_id.to_string()));
    }

    #[test]
    fn test_achievable_goals() {
        let planner = AttackPlanner::new();

        let goals = planner.get_achievable_goals();
        // At minimum, some recon-based goals should be achievable
        assert!(!goals.is_empty());
    }

    #[test]
    fn test_parameter_type_inference() {
        assert_eq!(ParameterType::from_name("user_id"), ParameterType::UserId);
        assert_eq!(ParameterType::from_name("email"), ParameterType::Email);
        assert_eq!(ParameterType::from_name("token"), ParameterType::Token);
        assert_eq!(ParameterType::from_name("file_path"), ParameterType::File);
        assert_eq!(ParameterType::from_name("redirect_url"), ParameterType::Url);
        assert_eq!(
            ParameterType::from_name("password"),
            ParameterType::Password
        );
        assert_eq!(ParameterType::from_name("random"), ParameterType::Other);
    }

    #[test]
    fn test_attack_plan_probability() {
        let steps = vec![
            AttackStep::new(
                "step1",
                "Step 1",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::Users,
                },
            )
            .with_success_rate(0.8),
            AttackStep::new(
                "step2",
                "Step 2",
                AttackStepType::Exploit {
                    vuln_type: "test".to_string(),
                    payload: None,
                },
            )
            .with_success_rate(0.5),
        ];

        let plan = AttackPlan::new(AttackGoal::AccountTakeover, steps);

        // Combined probability: 0.8 * 0.5 = 0.4
        assert!((plan.estimated_success - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_plan_advancement() {
        let steps = vec![
            AttackStep::new(
                "step1",
                "Step 1",
                AttackStepType::Enumerate {
                    target: EnumerationTarget::Users,
                },
            ),
            AttackStep::new(
                "step2",
                "Step 2",
                AttackStepType::Exploit {
                    vuln_type: "test".to_string(),
                    payload: None,
                },
            ),
        ];

        let mut plan = AttackPlan::new(AttackGoal::AccountTakeover, steps);

        assert_eq!(plan.current_step, 0);
        assert_eq!(plan.remaining_steps(), 2);

        plan.advance();
        assert_eq!(plan.current_step, 1);
        assert_eq!(plan.remaining_steps(), 1);

        plan.advance();
        assert!(plan.is_complete());
    }

    #[test]
    fn test_bfs_path_finding() {
        let mut planner = AttackPlanner::new();

        // Add a vulnerability that enables a path
        planner.update_state(StateUpdate::VulnFound(
            KnownVulnerability::new("XSS".to_string(), "/search".to_string(), Severity::High)
                .with_exploitable(true),
        ));

        // Should find a path to account takeover via XSS session hijack
        let plan = planner.plan_attack(AttackGoal::AccountTakeover);
        assert!(plan.is_some());
    }

    #[test]
    fn test_session_info_creation() {
        let anonymous = SessionInfo::anonymous();
        assert_eq!(anonymous.user_type, UserType::Anonymous);

        let regular = SessionInfo::regular_user("user123".to_string());
        assert_eq!(regular.user_type, UserType::Regular);
        assert_eq!(regular.user_id, Some("user123".to_string()));

        let admin = SessionInfo::admin("admin1".to_string());
        assert_eq!(admin.user_type, UserType::Admin);
    }

    #[test]
    fn test_severity_weights() {
        assert_eq!(Severity::Critical.weight(), 1.0);
        assert_eq!(Severity::High.weight(), 0.8);
        assert_eq!(Severity::Medium.weight(), 0.5);
        assert_eq!(Severity::Low.weight(), 0.3);
        assert_eq!(Severity::Info.weight(), 0.1);
    }

    #[test]
    fn test_planner_stats() {
        let mut planner = AttackPlanner::new();

        planner.update_state(StateUpdate::UserFound("user1".to_string()));
        planner.update_state(StateUpdate::UserFound("user2".to_string()));
        planner.update_state(StateUpdate::EndpointFound("/api/users".to_string()));

        let stats = planner.get_stats();
        assert_eq!(stats.known_users, 2);
        assert_eq!(stats.known_endpoints, 1);
        assert!(stats.available_steps > 0);
    }

    #[test]
    fn test_outcome_application() {
        let mut state = AttackState::new();

        Outcome::GainsSession(UserType::Admin).apply(&mut state);
        assert!(state.has_admin_session());

        Outcome::GainsInternalAccess.apply(&mut state);
        assert!(!state.internal_ips_found.is_empty());

        Outcome::DiscoversVulnerability("XSS".to_string()).apply(&mut state);
        assert!(state.has_vulnerability("XSS"));
    }

    #[test]
    fn test_data_exfiltration_chain() {
        let mut planner = AttackPlanner::new();

        // Add SSRF vulnerability
        planner.update_state(StateUpdate::VulnFound(
            KnownVulnerability::new("SSRF".to_string(), "/fetch".to_string(), Severity::High)
                .with_exploitable(true),
        ));

        let plan = planner.plan_attack(AttackGoal::DataExfiltration);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        // Should include steps for SSRF exploitation
        assert!(plan
            .steps
            .iter()
            .any(|s| s.name.to_lowercase().contains("ssrf")
                || s.name.to_lowercase().contains("cloud")
                || s.name.to_lowercase().contains("internal")));
    }

    #[test]
    fn test_privesc_chain() {
        let mut planner = AttackPlanner::new();

        // Add session and IDOR vulnerability
        planner.update_state(StateUpdate::SessionGained(
            "user_session".to_string(),
            SessionInfo::regular_user("user1".to_string()),
        ));
        planner.update_state(StateUpdate::VulnFound(
            KnownVulnerability::new("IDOR".to_string(), "/api/users".to_string(), Severity::High)
                .with_exploitable(true),
        ));

        let plan = planner.plan_attack(AttackGoal::PrivilegeEscalation);
        assert!(plan.is_some());
    }
}
