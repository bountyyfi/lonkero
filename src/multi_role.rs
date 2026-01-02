// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Multi-Role Parallel Testing Module
//!
//! This module enables parallel crawling with different user roles to detect
//! authorization vulnerabilities including:
//! - Horizontal privilege escalation (user A accessing user B's data)
//! - Vertical privilege escalation (user accessing admin functions)
//! - Broken Object Level Authorization (BOLA)
//! - Broken Function Level Authorization (BFLA)
//!
//! The orchestrator manages multiple authenticated browser sessions and
//! compares access patterns between roles to identify authorization issues.

#![allow(dead_code)]

use crate::auth_context::{AuthSession, Authenticator, LoginCredentials};
use crate::crawler::CrawlResults;
use crate::headless_crawler::{HeadlessCrawler, HeadlessCrawlerConfig};
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, Severity, Vulnerability};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{error, info, warn};

// ============================================================================
// Role Permission Levels
// ============================================================================

/// Permission level representing the hierarchy of roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermissionLevel {
    /// No authentication (guest/anonymous)
    Guest = 0,
    /// Basic authenticated user
    User = 1,
    /// Moderator or power user
    Moderator = 2,
    /// Administrator
    Admin = 3,
    /// Super admin or system level
    SuperAdmin = 4,
}

impl Default for PermissionLevel {
    fn default() -> Self {
        PermissionLevel::Guest
    }
}

impl std::fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionLevel::Guest => write!(f, "guest"),
            PermissionLevel::User => write!(f, "user"),
            PermissionLevel::Moderator => write!(f, "moderator"),
            PermissionLevel::Admin => write!(f, "admin"),
            PermissionLevel::SuperAdmin => write!(f, "superadmin"),
        }
    }
}

impl PermissionLevel {
    /// Parse permission level from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "guest" | "anonymous" | "unauthenticated" => PermissionLevel::Guest,
            "user" | "basic" | "member" => PermissionLevel::User,
            "moderator" | "mod" | "power" => PermissionLevel::Moderator,
            "admin" | "administrator" => PermissionLevel::Admin,
            "superadmin" | "super_admin" | "root" | "system" => PermissionLevel::SuperAdmin,
            _ => PermissionLevel::User,
        }
    }

    /// Check if this level is higher than another
    pub fn is_higher_than(&self, other: &PermissionLevel) -> bool {
        (*self as u8) > (*other as u8)
    }

    /// Check if this level is lower than another
    pub fn is_lower_than(&self, other: &PermissionLevel) -> bool {
        (*self as u8) < (*other as u8)
    }
}

// ============================================================================
// User Role Definition
// ============================================================================

/// Represents a user role with credentials and permissions
#[derive(Debug, Clone)]
pub struct UserRole {
    /// Unique identifier for this role
    pub name: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Login credentials for this role
    pub credentials: LoginCredentials,
    /// Permission level for authorization comparison
    pub permission_level: PermissionLevel,
    /// Known resources owned by this role (for IDOR detection)
    pub owned_resources: HashSet<String>,
    /// User identifier (e.g., user ID, email) for ownership checks
    pub user_identifier: Option<String>,
    /// Additional headers to send with requests (API keys, etc.)
    pub extra_headers: HashMap<String, String>,
}

impl UserRole {
    /// Create a new user role
    pub fn new(name: &str, username: &str, password: &str) -> Self {
        Self {
            name: name.to_string(),
            description: None,
            credentials: LoginCredentials::new(username, password),
            permission_level: PermissionLevel::User,
            owned_resources: HashSet::new(),
            user_identifier: Some(username.to_string()),
            extra_headers: HashMap::new(),
        }
    }

    /// Create a guest role (no authentication)
    pub fn guest() -> Self {
        Self {
            name: "guest".to_string(),
            description: Some("Unauthenticated user".to_string()),
            credentials: LoginCredentials::new("", ""),
            permission_level: PermissionLevel::Guest,
            owned_resources: HashSet::new(),
            user_identifier: None,
            extra_headers: HashMap::new(),
        }
    }

    /// Set the permission level
    pub fn with_permission_level(mut self, level: PermissionLevel) -> Self {
        self.permission_level = level;
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set login URL
    pub fn with_login_url(mut self, url: &str) -> Self {
        self.credentials = self.credentials.with_login_url(url);
        self
    }

    /// Add an owned resource identifier
    pub fn with_owned_resource(mut self, resource: &str) -> Self {
        self.owned_resources.insert(resource.to_string());
        self
    }

    /// Add multiple owned resources
    pub fn with_owned_resources(mut self, resources: Vec<&str>) -> Self {
        for resource in resources {
            self.owned_resources.insert(resource.to_string());
        }
        self
    }

    /// Set user identifier
    pub fn with_user_identifier(mut self, id: &str) -> Self {
        self.user_identifier = Some(id.to_string());
        self
    }

    /// Add extra header
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.extra_headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Check if this role is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.permission_level != PermissionLevel::Guest
    }
}

// ============================================================================
// Role Session (Active Session for a Role)
// ============================================================================

/// Active authenticated session for a specific role
#[derive(Debug, Clone)]
pub struct RoleSession {
    /// The role this session belongs to
    pub role: UserRole,
    /// Authentication session data (cookies, tokens, etc.)
    pub auth_session: AuthSession,
    /// Whether login was successful
    pub is_active: bool,
    /// Session creation time
    pub created_at: std::time::Instant,
    /// URLs that have been crawled with this session
    pub crawled_urls: HashSet<String>,
    /// HTTP responses received (URL -> response metadata)
    pub responses: HashMap<String, ResponseMetadata>,
}

/// Metadata about an HTTP response (avoiding storing full body for memory efficiency)
#[derive(Debug, Clone)]
pub struct ResponseMetadata {
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
    pub content_type: Option<String>,
    pub contains_user_data: bool,
    pub response_hash: u64,
    /// Key identifiers found in the response (user IDs, emails, etc.)
    pub found_identifiers: HashSet<String>,
    /// Whether the response appears to be an error
    pub is_error: bool,
    /// Redirect target if this was a redirect
    pub redirect_location: Option<String>,
}

impl ResponseMetadata {
    /// Create metadata from an HTTP response
    pub fn from_response(response: &HttpResponse, url: &str) -> Self {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        response.body.hash(&mut hasher);
        let response_hash = hasher.finish();

        let content_type = response.headers.get("content-type").cloned();
        let is_error = response.status_code >= 400;
        let redirect_location = if response.status_code >= 300 && response.status_code < 400 {
            response.headers.get("location").cloned()
        } else {
            None
        };

        Self {
            url: url.to_string(),
            status_code: response.status_code,
            content_length: response.body.len(),
            content_type,
            contains_user_data: Self::detect_user_data(&response.body),
            response_hash,
            found_identifiers: Self::extract_identifiers(&response.body),
            is_error,
            redirect_location,
        }
    }

    /// Detect if response contains user-specific data
    fn detect_user_data(body: &str) -> bool {
        let patterns = [
            "\"email\":", "\"username\":", "\"name\":", "\"profile\":",
            "\"account\":", "\"user_id\":", "\"userId\":", "\"id\":",
            "\"phone\":", "\"address\":", "\"balance\":", "\"credit\":",
            "\"ssn\":", "\"password\":", "\"token\":", "\"apiKey\":",
        ];

        patterns.iter().any(|p| body.contains(p))
    }

    /// Extract potential identifiers from response
    fn extract_identifiers(body: &str) -> HashSet<String> {
        let mut identifiers = HashSet::new();

        // Extract email addresses
        let email_regex = regex::Regex::new(r#""[^"]*@[^"]+\.[^"]+""#).ok();
        if let Some(re) = email_regex {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(0) {
                    identifiers.insert(m.as_str().trim_matches('"').to_string());
                }
            }
        }

        // Extract numeric IDs from common patterns
        let id_regex = regex::Regex::new(r#""(?:id|user_id|userId|account_id)"\s*:\s*(\d+)"#).ok();
        if let Some(re) = id_regex {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(1) {
                    identifiers.insert(format!("id:{}", m.as_str()));
                }
            }
        }

        // Extract UUIDs
        let uuid_regex = regex::Regex::new(r#"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#).ok();
        if let Some(re) = uuid_regex {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(0) {
                    identifiers.insert(format!("uuid:{}", m.as_str()));
                }
            }
        }

        identifiers
    }

    /// Check if this response indicates successful access
    pub fn indicates_access(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300 && !self.is_error
    }

    /// Check if this response indicates forbidden access
    pub fn indicates_forbidden(&self) -> bool {
        self.status_code == 403 || self.status_code == 401
    }
}

impl RoleSession {
    /// Create a new session for a role
    pub fn new(role: UserRole, auth_session: AuthSession) -> Self {
        Self {
            role,
            is_active: auth_session.is_authenticated,
            auth_session,
            created_at: std::time::Instant::now(),
            crawled_urls: HashSet::new(),
            responses: HashMap::new(),
        }
    }

    /// Create a guest session (no authentication)
    pub fn guest() -> Self {
        Self::new(UserRole::guest(), AuthSession::empty())
    }

    /// Add a response for a URL
    pub fn add_response(&mut self, url: &str, response: &HttpResponse) {
        let metadata = ResponseMetadata::from_response(response, url);
        self.responses.insert(url.to_string(), metadata);
        self.crawled_urls.insert(url.to_string());
    }

    /// Get response metadata for a URL
    pub fn get_response(&self, url: &str) -> Option<&ResponseMetadata> {
        self.responses.get(url)
    }

    /// Check if a specific URL has been accessed
    pub fn has_accessed(&self, url: &str) -> bool {
        self.crawled_urls.contains(url)
    }

    /// Get all accessible URLs (2xx responses)
    pub fn get_accessible_urls(&self) -> HashSet<String> {
        self.responses
            .iter()
            .filter(|(_, meta)| meta.indicates_access())
            .map(|(url, _)| url.clone())
            .collect()
    }

    /// Get all forbidden URLs (401/403 responses)
    pub fn get_forbidden_urls(&self) -> HashSet<String> {
        self.responses
            .iter()
            .filter(|(_, meta)| meta.indicates_forbidden())
            .map(|(url, _)| url.clone())
            .collect()
    }
}

// ============================================================================
// Role Comparison Results
// ============================================================================

/// Comparison between what different roles can access
#[derive(Debug, Clone)]
pub struct RoleComparison {
    /// The two roles being compared
    pub role_a: String,
    pub role_b: String,
    /// Permission levels
    pub level_a: PermissionLevel,
    pub level_b: PermissionLevel,
    /// URLs accessible by role A but not role B
    pub exclusive_to_a: HashSet<String>,
    /// URLs accessible by role B but not role A
    pub exclusive_to_b: HashSet<String>,
    /// URLs accessible by both roles
    pub shared_access: HashSet<String>,
    /// Potential vertical escalation issues (lower accessing higher's resources)
    pub vertical_escalations: Vec<EscalationFinding>,
    /// Potential horizontal escalation issues (accessing other user's data)
    pub horizontal_escalations: Vec<EscalationFinding>,
    /// Access matrix entries
    pub access_matrix: Vec<AccessMatrixEntry>,
}

/// Single entry in the access matrix
#[derive(Debug, Clone)]
pub struct AccessMatrixEntry {
    pub url: String,
    pub role_access: HashMap<String, AccessResult>,
}

/// Result of access attempt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessResult {
    /// Access granted (2xx response)
    Granted,
    /// Access denied (401/403)
    Denied,
    /// Redirect occurred
    Redirect(String),
    /// Error occurred
    Error(u16),
    /// Not tested
    NotTested,
}

impl std::fmt::Display for AccessResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessResult::Granted => write!(f, "GRANTED"),
            AccessResult::Denied => write!(f, "DENIED"),
            AccessResult::Redirect(loc) => write!(f, "REDIRECT({})", loc),
            AccessResult::Error(code) => write!(f, "ERROR({})", code),
            AccessResult::NotTested => write!(f, "NOT_TESTED"),
        }
    }
}

/// A potential privilege escalation finding
#[derive(Debug, Clone)]
pub struct EscalationFinding {
    /// Type of escalation
    pub escalation_type: EscalationType,
    /// The URL/resource that was accessed
    pub resource_url: String,
    /// The role that shouldn't have access
    pub accessor_role: String,
    /// The role that should have exclusive access
    pub owner_role: String,
    /// Confidence level
    pub confidence: Confidence,
    /// Evidence supporting the finding
    pub evidence: String,
    /// Whether identifiers from owner were found in accessor's response
    pub found_other_user_data: bool,
    /// Specific identifiers that were leaked
    pub leaked_identifiers: HashSet<String>,
}

/// Type of privilege escalation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationType {
    /// Lower role accessing higher role's functionality
    Vertical,
    /// Same level role accessing another user's data
    Horizontal,
    /// Both vertical and horizontal issues
    Both,
}

impl std::fmt::Display for EscalationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscalationType::Vertical => write!(f, "Vertical"),
            EscalationType::Horizontal => write!(f, "Horizontal"),
            EscalationType::Both => write!(f, "Vertical+Horizontal"),
        }
    }
}

impl RoleComparison {
    /// Create a new comparison between two roles
    pub fn new(role_a: &str, level_a: PermissionLevel, role_b: &str, level_b: PermissionLevel) -> Self {
        Self {
            role_a: role_a.to_string(),
            role_b: role_b.to_string(),
            level_a,
            level_b,
            exclusive_to_a: HashSet::new(),
            exclusive_to_b: HashSet::new(),
            shared_access: HashSet::new(),
            vertical_escalations: Vec::new(),
            horizontal_escalations: Vec::new(),
            access_matrix: Vec::new(),
        }
    }

    /// Check if there are any escalation findings
    pub fn has_findings(&self) -> bool {
        !self.vertical_escalations.is_empty() || !self.horizontal_escalations.is_empty()
    }

    /// Get total number of findings
    pub fn finding_count(&self) -> usize {
        self.vertical_escalations.len() + self.horizontal_escalations.len()
    }

    /// Convert findings to vulnerabilities
    pub fn to_vulnerabilities(&self) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for finding in &self.vertical_escalations {
            vulns.push(self.escalation_to_vulnerability(finding));
        }

        for finding in &self.horizontal_escalations {
            vulns.push(self.escalation_to_vulnerability(finding));
        }

        vulns
    }

    fn escalation_to_vulnerability(&self, finding: &EscalationFinding) -> Vulnerability {
        let (vuln_type, description, cwe, cvss) = match finding.escalation_type {
            EscalationType::Vertical => (
                "Vertical Privilege Escalation".to_string(),
                format!(
                    "Role '{}' (permission level: {}) can access resources belonging to higher-privileged role '{}'. \
                     This indicates missing authorization checks that allow lower-privileged users to access \
                     administrative or elevated functions.",
                    finding.accessor_role, self.level_a, finding.owner_role
                ),
                "CWE-269".to_string(),
                8.8,
            ),
            EscalationType::Horizontal => (
                "Horizontal Privilege Escalation (IDOR)".to_string(),
                format!(
                    "Role '{}' can access resources belonging to another user '{}' at the same permission level. \
                     This indicates broken object-level authorization allowing users to access other users' data.",
                    finding.accessor_role, finding.owner_role
                ),
                "CWE-639".to_string(),
                8.1,
            ),
            EscalationType::Both => (
                "Multi-Vector Privilege Escalation".to_string(),
                format!(
                    "Role '{}' can access resources belonging to '{}' through combined vertical and horizontal \
                     privilege escalation. This represents a severe authorization bypass.",
                    finding.accessor_role, finding.owner_role
                ),
                "CWE-863".to_string(),
                9.1,
            ),
        };

        let severity = if cvss >= 9.0 {
            Severity::Critical
        } else if cvss >= 7.0 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut evidence_details = finding.evidence.clone();
        if finding.found_other_user_data && !finding.leaked_identifiers.is_empty() {
            evidence_details.push_str(&format!(
                "\n\nLeaked identifiers found in response: {:?}",
                finding.leaked_identifiers
            ));
        }

        Vulnerability {
            id: format!("priv_esc_{}", uuid::Uuid::new_v4()),
            vuln_type,
            severity,
            confidence: finding.confidence.clone(),
            category: "Authorization".to_string(),
            url: finding.resource_url.clone(),
            parameter: None,
            payload: String::new(),
            description,
            evidence: Some(evidence_details),
            cwe,
            cvss,
            verified: true,
            false_positive: false,
            remediation: "1. Implement proper authorization checks at every endpoint\n\
                         2. Verify object ownership before returning data\n\
                         3. Use role-based access control (RBAC) or attribute-based access control (ABAC)\n\
                         4. Implement object-level authorization for all data access\n\
                         5. Use indirect references instead of direct object IDs\n\
                         6. Log and monitor for suspicious access patterns\n\
                         7. Implement the principle of least privilege"
                .to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }
}

// ============================================================================
// Multi-Role Orchestrator Configuration
// ============================================================================

/// Configuration for the multi-role orchestrator
#[derive(Debug, Clone)]
pub struct MultiRoleConfig {
    /// Maximum concurrent browser instances
    pub max_concurrent_browsers: usize,
    /// Timeout for each browser session (seconds)
    pub browser_timeout_secs: u64,
    /// Maximum URLs to crawl per role
    pub max_urls_per_role: usize,
    /// Whether to compare response content (more accurate but slower)
    pub compare_response_content: bool,
    /// URLs to always test (regardless of crawling)
    pub mandatory_test_urls: Vec<String>,
    /// URL patterns to skip
    pub skip_url_patterns: Vec<String>,
    /// Whether to perform headless crawling (vs HTTP only)
    pub enable_headless_crawling: bool,
    /// Delay between requests (ms) to avoid rate limiting
    pub request_delay_ms: u64,
    /// Whether to test API endpoints discovered during crawling
    pub test_api_endpoints: bool,
}

impl Default for MultiRoleConfig {
    fn default() -> Self {
        Self {
            max_concurrent_browsers: 4,
            browser_timeout_secs: 60,
            max_urls_per_role: 100,
            compare_response_content: true,
            mandatory_test_urls: Vec::new(),
            skip_url_patterns: vec![
                r"\.css$".to_string(),
                r"\.js$".to_string(),
                r"\.png$".to_string(),
                r"\.jpg$".to_string(),
                r"\.gif$".to_string(),
                r"\.svg$".to_string(),
                r"\.ico$".to_string(),
                r"\.woff".to_string(),
                r"/static/".to_string(),
                r"/assets/".to_string(),
            ],
            enable_headless_crawling: true,
            request_delay_ms: 100,
            test_api_endpoints: true,
        }
    }
}

// ============================================================================
// Multi-Role Orchestrator
// ============================================================================

/// Orchestrates parallel crawling with multiple user roles
pub struct MultiRoleOrchestrator {
    /// Configuration
    config: MultiRoleConfig,
    /// HTTP client for API requests
    http_client: Arc<HttpClient>,
    /// Authenticator for login
    authenticator: Authenticator,
    /// Active sessions by role name
    sessions: Arc<RwLock<HashMap<String, RoleSession>>>,
    /// Semaphore for limiting concurrent browsers
    browser_semaphore: Arc<Semaphore>,
    /// URLs discovered across all roles
    discovered_urls: Arc<Mutex<HashSet<String>>>,
    /// API endpoints discovered
    discovered_api_endpoints: Arc<Mutex<HashSet<String>>>,
}

impl MultiRoleOrchestrator {
    /// Create a new multi-role orchestrator
    pub fn new(http_client: Arc<HttpClient>, config: MultiRoleConfig) -> Self {
        let browser_semaphore = Arc::new(Semaphore::new(config.max_concurrent_browsers));

        Self {
            authenticator: Authenticator::new(config.browser_timeout_secs),
            config,
            http_client,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            browser_semaphore,
            discovered_urls: Arc::new(Mutex::new(HashSet::new())),
            discovered_api_endpoints: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Initialize sessions for all provided roles
    pub async fn initialize_sessions(&self, base_url: &str, roles: Vec<UserRole>) -> Result<()> {
        info!("[MultiRole] Initializing {} role sessions", roles.len());

        let mut handles = Vec::new();

        for role in roles {
            let authenticator = Authenticator::new(self.config.browser_timeout_secs);
            let base_url = base_url.to_string();
            let sessions = self.sessions.clone();
            let semaphore = self.browser_semaphore.clone();

            let handle = tokio::spawn(async move {
                // Acquire browser slot
                let _permit = semaphore.acquire().await.ok();

                let session = if role.permission_level == PermissionLevel::Guest {
                    info!("[MultiRole] Creating guest session (no login required)");
                    RoleSession::guest()
                } else {
                    info!("[MultiRole] Authenticating role: {}", role.name);
                    match authenticator.login(&base_url, &role.credentials).await {
                        Ok(auth_session) => {
                            if auth_session.is_authenticated {
                                info!(
                                    "[MultiRole] Successfully authenticated role: {}",
                                    role.name
                                );
                                RoleSession::new(role.clone(), auth_session)
                            } else {
                                warn!(
                                    "[MultiRole] Authentication failed for role: {}",
                                    role.name
                                );
                                let mut session = RoleSession::new(role.clone(), auth_session);
                                session.is_active = false;
                                session
                            }
                        }
                        Err(e) => {
                            error!(
                                "[MultiRole] Login error for role {}: {}",
                                role.name, e
                            );
                            let mut session =
                                RoleSession::new(role.clone(), AuthSession::empty());
                            session.is_active = false;
                            session
                        }
                    }
                };

                let role_name = session.role.name.clone();
                sessions.write().await.insert(role_name, session);
            });

            handles.push(handle);
        }

        // Wait for all authentication to complete
        for handle in handles {
            let _ = handle.await;
        }

        let active_count = self
            .sessions
            .read()
            .await
            .values()
            .filter(|s| s.is_active)
            .count();

        info!(
            "[MultiRole] Session initialization complete: {} active sessions",
            active_count
        );

        Ok(())
    }

    /// Perform synchronized crawling across all roles
    pub async fn synchronized_crawl(&self, base_url: &str) -> Result<HashMap<String, CrawlResults>> {
        info!("[MultiRole] Starting synchronized crawl from {}", base_url);

        let sessions = self.sessions.read().await;
        let active_roles: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.is_active || s.role.permission_level == PermissionLevel::Guest)
            .map(|(name, _)| name.clone())
            .collect();
        drop(sessions);

        if active_roles.is_empty() {
            warn!("[MultiRole] No active sessions for crawling");
            return Ok(HashMap::new());
        }

        let mut results: HashMap<String, CrawlResults> = HashMap::new();

        // Phase 1: Collect URLs to test from mandatory list and initial crawl
        let mut urls_to_test: HashSet<String> = HashSet::new();
        urls_to_test.insert(base_url.to_string());
        urls_to_test.extend(self.config.mandatory_test_urls.iter().cloned());

        // Phase 2: Do initial discovery with the highest privileged role
        let highest_role = self.get_highest_privileged_role().await;
        if let Some(role_name) = highest_role {
            info!(
                "[MultiRole] Using '{}' role for initial URL discovery",
                role_name
            );
            let discovered = self.crawl_for_role(&role_name, base_url).await?;
            urls_to_test.extend(discovered.links.iter().cloned());
            urls_to_test.extend(discovered.api_endpoints.iter().cloned());

            // Store discovered URLs globally
            {
                let mut global_urls = self.discovered_urls.lock().await;
                global_urls.extend(urls_to_test.iter().cloned());
            }

            results.insert(role_name, discovered);
        }

        // Phase 3: Filter URLs based on skip patterns
        let urls_to_test: Vec<String> = urls_to_test
            .into_iter()
            .filter(|url| !self.should_skip_url(url))
            .take(self.config.max_urls_per_role)
            .collect();

        info!(
            "[MultiRole] Testing {} URLs across {} roles",
            urls_to_test.len(),
            active_roles.len()
        );

        // Phase 4: Test all URLs with all roles in parallel
        for role_name in &active_roles {
            if results.contains_key(role_name) {
                continue; // Already crawled as discovery role
            }

            let role_results = self.test_urls_for_role(role_name, &urls_to_test).await?;
            results.insert(role_name.clone(), role_results);
        }

        // Update sessions with crawl results
        self.update_sessions_with_results(&results).await;

        info!("[MultiRole] Synchronized crawl complete");
        Ok(results)
    }

    /// Get the highest privileged active role
    async fn get_highest_privileged_role(&self) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .filter(|(_, s)| s.is_active)
            .max_by_key(|(_, s)| s.role.permission_level as u8)
            .map(|(name, _)| name.clone())
    }

    /// Crawl URLs for a specific role
    async fn crawl_for_role(&self, role_name: &str, base_url: &str) -> Result<CrawlResults> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(role_name)
            .context("Role session not found")?;

        let mut results = CrawlResults::new();
        results.crawled_urls.insert(base_url.to_string());

        if self.config.enable_headless_crawling && session.is_active {
            // Use headless browser for JavaScript-rendered content
            let _permit = self.browser_semaphore.acquire().await?;

            let token = session.auth_session.find_jwt();
            // Include role-specific extra_headers and auth headers for headless crawling
            let mut headless_headers = session.auth_session.auth_headers().into_iter().collect::<HashMap<_, _>>();
            headless_headers.extend(session.role.extra_headers.clone());

            let crawler = HeadlessCrawler::with_headers_and_config(
                self.config.browser_timeout_secs,
                token,
                headless_headers,
                HeadlessCrawlerConfig {
                    max_pages: self.config.max_urls_per_role,
                    ..Default::default()
                },
            );

            if let Ok(forms) = crawler.extract_forms(base_url).await {
                results.forms = forms;
            }
        }

        // Also do HTTP-based crawling to find links
        let auth_headers = session.auth_session.auth_headers();
        drop(sessions);

        let response = self.http_client.get_with_headers(base_url, auth_headers).await?;

        // Extract links from response
        self.extract_links_from_response(&response.body, base_url, &mut results);

        Ok(results)
    }

    /// Test specific URLs for a role
    async fn test_urls_for_role(
        &self,
        role_name: &str,
        urls: &[String],
    ) -> Result<CrawlResults> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(role_name)
            .context("Role session not found")?;

        let auth_headers = session.auth_session.auth_headers();
        let extra_headers: Vec<(String, String)> = session
            .role
            .extra_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        drop(sessions);

        let mut results = CrawlResults::new();
        let mut all_headers = auth_headers;
        all_headers.extend(extra_headers);

        for url in urls {
            if let Ok(response) = self.http_client.get_with_headers(url, all_headers.clone()).await {
                results.crawled_urls.insert(url.clone());

                // Store response metadata in session
                let mut sessions = self.sessions.write().await;
                if let Some(session) = sessions.get_mut(role_name) {
                    session.add_response(url, &response);
                }

                // Extract additional links
                self.extract_links_from_response(&response.body, url, &mut results);
            }

            // Respect rate limiting
            if self.config.request_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.request_delay_ms)).await;
            }
        }

        Ok(results)
    }

    /// Extract links from HTML response
    fn extract_links_from_response(&self, body: &str, base_url: &str, results: &mut CrawlResults) {
        let base = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return,
        };

        // Extract href links
        let href_regex = regex::Regex::new(r#"href=["']([^"']+)["']"#).ok();
        if let Some(re) = href_regex {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(1) {
                    if let Ok(absolute) = base.join(m.as_str()) {
                        if absolute.host() == base.host() {
                            results.links.insert(absolute.to_string());
                        }
                    }
                }
            }
        }

        // Extract API endpoints
        let api_regex = regex::Regex::new(r#"["'](/api/[^"']+)["']"#).ok();
        if let Some(re) = api_regex {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(1) {
                    if let Ok(absolute) = base.join(m.as_str()) {
                        results.api_endpoints.insert(absolute.to_string());
                    }
                }
            }
        }
    }

    /// Update sessions with crawl results
    async fn update_sessions_with_results(&self, results: &HashMap<String, CrawlResults>) {
        let mut sessions = self.sessions.write().await;

        for (role_name, crawl_results) in results {
            if let Some(session) = sessions.get_mut(role_name) {
                session.crawled_urls.extend(crawl_results.crawled_urls.iter().cloned());
            }
        }
    }

    /// Check if a URL should be skipped
    fn should_skip_url(&self, url: &str) -> bool {
        for pattern in &self.config.skip_url_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(url) {
                    return true;
                }
            }
        }
        false
    }

    /// Compare access patterns between all roles and detect authorization issues
    pub async fn compare_all_roles(&self) -> Result<Vec<RoleComparison>> {
        info!("[MultiRole] Comparing access patterns between roles");

        let sessions = self.sessions.read().await;
        let roles: Vec<&RoleSession> = sessions.values().collect();

        if roles.len() < 2 {
            warn!("[MultiRole] Need at least 2 roles for comparison");
            return Ok(Vec::new());
        }

        let mut comparisons = Vec::new();

        // Compare each pair of roles
        for i in 0..roles.len() {
            for j in (i + 1)..roles.len() {
                let role_a = &roles[i];
                let role_b = &roles[j];

                let comparison = self.compare_two_roles(role_a, role_b);
                if comparison.has_findings() {
                    comparisons.push(comparison);
                }
            }
        }

        info!(
            "[MultiRole] Role comparison complete: {} comparisons with findings",
            comparisons.len()
        );

        Ok(comparisons)
    }

    /// Compare two specific roles
    fn compare_two_roles(&self, role_a: &RoleSession, role_b: &RoleSession) -> RoleComparison {
        let mut comparison = RoleComparison::new(
            &role_a.role.name,
            role_a.role.permission_level,
            &role_b.role.name,
            role_b.role.permission_level,
        );

        let accessible_a = role_a.get_accessible_urls();
        let accessible_b = role_b.get_accessible_urls();

        // Calculate set differences
        comparison.exclusive_to_a = accessible_a.difference(&accessible_b).cloned().collect();
        comparison.exclusive_to_b = accessible_b.difference(&accessible_a).cloned().collect();
        comparison.shared_access = accessible_a.intersection(&accessible_b).cloned().collect();

        // Build access matrix
        let all_urls: HashSet<String> = role_a
            .crawled_urls
            .union(&role_b.crawled_urls)
            .cloned()
            .collect();

        for url in &all_urls {
            let mut entry = AccessMatrixEntry {
                url: url.clone(),
                role_access: HashMap::new(),
            };

            entry.role_access.insert(
                role_a.role.name.clone(),
                self.get_access_result(role_a.get_response(url)),
            );
            entry.role_access.insert(
                role_b.role.name.clone(),
                self.get_access_result(role_b.get_response(url)),
            );

            comparison.access_matrix.push(entry);
        }

        // Detect vertical privilege escalation
        // Lower role accessing higher role's exclusive resources
        self.detect_vertical_escalation(&mut comparison, role_a, role_b);
        self.detect_vertical_escalation(&mut comparison, role_b, role_a);

        // Detect horizontal privilege escalation
        // Same-level roles accessing each other's user-specific data
        self.detect_horizontal_escalation(&mut comparison, role_a, role_b);

        comparison
    }

    /// Get access result from response metadata
    fn get_access_result(&self, metadata: Option<&ResponseMetadata>) -> AccessResult {
        match metadata {
            None => AccessResult::NotTested,
            Some(meta) => {
                if meta.indicates_access() {
                    AccessResult::Granted
                } else if meta.indicates_forbidden() {
                    AccessResult::Denied
                } else if let Some(ref loc) = meta.redirect_location {
                    AccessResult::Redirect(loc.clone())
                } else {
                    AccessResult::Error(meta.status_code)
                }
            }
        }
    }

    /// Detect vertical privilege escalation
    fn detect_vertical_escalation(
        &self,
        comparison: &mut RoleComparison,
        lower_role: &RoleSession,
        higher_role: &RoleSession,
    ) {
        // Skip if roles are at the same level or lower_role is actually higher
        if !lower_role
            .role
            .permission_level
            .is_lower_than(&higher_role.role.permission_level)
        {
            return;
        }

        // Check if lower role can access higher role's exclusive URLs
        let higher_accessible = higher_role.get_accessible_urls();
        let higher_forbidden_for_lower: HashSet<String> = higher_role
            .responses
            .iter()
            .filter(|(url, meta)| {
                meta.indicates_access()
                    && lower_role
                        .get_response(url)
                        .map(|m| m.indicates_forbidden())
                        .unwrap_or(true)
            })
            .map(|(url, _)| url.clone())
            .collect();

        // URLs that should be admin-only but lower role can access
        for url in &higher_accessible {
            if let Some(lower_meta) = lower_role.get_response(url) {
                if lower_meta.indicates_access() {
                    // Lower role CAN access what should be higher-only
                    // Check if this looks like a sensitive admin endpoint
                    let is_sensitive = self.is_sensitive_admin_endpoint(url);

                    if is_sensitive || self.config.compare_response_content {
                        let higher_meta = higher_role.get_response(url);
                        let content_matches = higher_meta.map(|h| {
                            h.response_hash == lower_meta.response_hash
                                || h.content_length.abs_diff(lower_meta.content_length) < 100
                        });

                        if content_matches.unwrap_or(false) {
                            let confidence = if is_sensitive {
                                Confidence::High
                            } else {
                                Confidence::Medium
                            };

                            comparison.vertical_escalations.push(EscalationFinding {
                                escalation_type: EscalationType::Vertical,
                                resource_url: url.clone(),
                                accessor_role: lower_role.role.name.clone(),
                                owner_role: higher_role.role.name.clone(),
                                confidence,
                                evidence: format!(
                                    "Role '{}' (level: {}) can access '{}' which appears to be \
                                     restricted to '{}' (level: {}). Response similarity indicates \
                                     same content is returned.",
                                    lower_role.role.name,
                                    lower_role.role.permission_level,
                                    url,
                                    higher_role.role.name,
                                    higher_role.role.permission_level
                                ),
                                found_other_user_data: false,
                                leaked_identifiers: HashSet::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if URL appears to be a sensitive admin endpoint
    fn is_sensitive_admin_endpoint(&self, url: &str) -> bool {
        let sensitive_patterns = [
            "/admin",
            "/dashboard",
            "/manage",
            "/settings",
            "/config",
            "/users",
            "/roles",
            "/permissions",
            "/audit",
            "/logs",
            "/system",
            "/internal",
            "/debug",
            "/api/admin",
            "/api/v1/admin",
            "/api/v2/admin",
        ];

        let url_lower = url.to_lowercase();
        sensitive_patterns.iter().any(|p| url_lower.contains(p))
    }

    /// Detect horizontal privilege escalation
    fn detect_horizontal_escalation(
        &self,
        comparison: &mut RoleComparison,
        role_a: &RoleSession,
        role_b: &RoleSession,
    ) {
        // Only check if roles are at the same permission level
        if role_a.role.permission_level != role_b.role.permission_level {
            return;
        }

        // Check if role_a can access role_b's user-specific data
        for (url, meta_a) in &role_a.responses {
            if !meta_a.indicates_access() || !meta_a.contains_user_data {
                continue;
            }

            // Check if identifiers from role_b appear in role_a's response
            if let Some(user_id_b) = &role_b.role.user_identifier {
                let contains_other_user_data = meta_a.found_identifiers.iter().any(|id| {
                    id.contains(user_id_b)
                        || role_b.role.owned_resources.iter().any(|r| id.contains(r))
                });

                if contains_other_user_data {
                    // Check if role_b also accessed this URL and got their own data
                    if let Some(meta_b) = role_b.get_response(url) {
                        if meta_b.indicates_access() && meta_b.contains_user_data {
                            // Both roles can access, but role_a sees role_b's data
                            comparison.horizontal_escalations.push(EscalationFinding {
                                escalation_type: EscalationType::Horizontal,
                                resource_url: url.clone(),
                                accessor_role: role_a.role.name.clone(),
                                owner_role: role_b.role.name.clone(),
                                confidence: Confidence::High,
                                evidence: format!(
                                    "Role '{}' response at '{}' contains identifiers belonging to \
                                     role '{}'. This indicates broken object-level authorization \
                                     allowing access to other users' data.",
                                    role_a.role.name, url, role_b.role.name
                                ),
                                found_other_user_data: true,
                                leaked_identifiers: meta_a.found_identifiers.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Generate access matrix for all roles and URLs
    pub async fn generate_access_matrix(&self) -> AccessMatrix {
        let sessions = self.sessions.read().await;

        let roles: Vec<String> = sessions.keys().cloned().collect();
        let all_urls: HashSet<String> = sessions
            .values()
            .flat_map(|s| s.crawled_urls.iter().cloned())
            .collect();

        let mut entries = Vec::new();

        for url in &all_urls {
            let mut role_access = HashMap::new();

            for (role_name, session) in sessions.iter() {
                let result = self.get_access_result(session.get_response(url));
                role_access.insert(role_name.clone(), result);
            }

            entries.push(AccessMatrixEntry {
                url: url.clone(),
                role_access,
            });
        }

        // Sort by URL for consistent output
        entries.sort_by(|a, b| a.url.cmp(&b.url));

        AccessMatrix { roles, entries }
    }

    /// Run full authorization analysis and return vulnerabilities
    pub async fn analyze_authorization(&self, base_url: &str) -> Result<Vec<Vulnerability>> {
        info!("[MultiRole] Starting full authorization analysis");

        // License check
        if !crate::license::verify_scan_authorized() {
            info!("[SKIP] Multi-role authorization testing requires valid license");
            return Ok(Vec::new());
        }

        // Step 1: Synchronized crawl
        let _crawl_results = self.synchronized_crawl(base_url).await?;

        // Step 2: Compare all role pairs
        let comparisons = self.compare_all_roles().await?;

        // Step 3: Convert findings to vulnerabilities
        let mut vulnerabilities = Vec::new();
        for comparison in comparisons {
            vulnerabilities.extend(comparison.to_vulnerabilities());
        }

        info!(
            "[MultiRole] Authorization analysis complete: {} vulnerabilities found",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }

    /// Get summary statistics
    pub async fn get_statistics(&self) -> MultiRoleStatistics {
        let sessions = self.sessions.read().await;

        let total_roles = sessions.len();
        let active_roles = sessions.values().filter(|s| s.is_active).count();
        let total_urls_tested: usize = sessions.values().map(|s| s.crawled_urls.len()).sum();
        let unique_urls: HashSet<String> = sessions
            .values()
            .flat_map(|s| s.crawled_urls.iter().cloned())
            .collect();

        MultiRoleStatistics {
            total_roles,
            active_roles,
            total_urls_tested,
            unique_urls_tested: unique_urls.len(),
            urls_per_role: sessions
                .iter()
                .map(|(name, s)| (name.clone(), s.crawled_urls.len()))
                .collect(),
        }
    }
}

/// Full access matrix for all roles
#[derive(Debug, Clone)]
pub struct AccessMatrix {
    pub roles: Vec<String>,
    pub entries: Vec<AccessMatrixEntry>,
}

impl AccessMatrix {
    /// Sanitize a CSV field to prevent CSV injection
    /// Prefixes values starting with =, +, -, @, or tab with a single quote
    fn sanitize_csv_field(field: &str) -> String {
        let field = field.replace(',', "%2C").replace('"', "\"\"");
        if field.starts_with('=') || field.starts_with('+') ||
           field.starts_with('-') || field.starts_with('@') ||
           field.starts_with('\t') || field.starts_with('\r') ||
           field.starts_with('\n') {
            format!("'{}", field)
        } else {
            field
        }
    }

    /// Export as CSV format
    pub fn to_csv(&self) -> String {
        let mut csv = String::new();

        // Header
        csv.push_str("URL");
        for role in &self.roles {
            csv.push(',');
            csv.push_str(&Self::sanitize_csv_field(role));
        }
        csv.push('\n');

        // Data rows
        for entry in &self.entries {
            csv.push_str(&Self::sanitize_csv_field(&entry.url));
            for role in &self.roles {
                csv.push(',');
                let result = entry
                    .role_access
                    .get(role)
                    .unwrap_or(&AccessResult::NotTested);
                csv.push_str(&Self::sanitize_csv_field(&result.to_string()));
            }
            csv.push('\n');
        }

        csv
    }

    /// Find authorization anomalies
    pub fn find_anomalies(&self) -> Vec<String> {
        let mut anomalies = Vec::new();

        for entry in &self.entries {
            let granted_roles: Vec<&String> = entry
                .role_access
                .iter()
                .filter(|(_, r)| **r == AccessResult::Granted)
                .map(|(name, _)| name)
                .collect();

            let denied_roles: Vec<&String> = entry
                .role_access
                .iter()
                .filter(|(_, r)| **r == AccessResult::Denied)
                .map(|(name, _)| name)
                .collect();

            // Anomaly: guest can access but authenticated user cannot
            if granted_roles.iter().any(|r| r.to_lowercase() == "guest")
                && denied_roles.iter().any(|r| r.to_lowercase() != "guest")
            {
                anomalies.push(format!(
                    "Guest can access {} but some authenticated roles cannot",
                    entry.url
                ));
            }

            // Anomaly: mix of granted and denied at same level (potential IDOR)
            if !granted_roles.is_empty() && !denied_roles.is_empty() && granted_roles.len() > 1 {
                anomalies.push(format!(
                    "Inconsistent access to {}: granted to {:?}, denied to {:?}",
                    entry.url, granted_roles, denied_roles
                ));
            }
        }

        anomalies
    }
}

/// Statistics about multi-role testing
#[derive(Debug, Clone)]
pub struct MultiRoleStatistics {
    pub total_roles: usize,
    pub active_roles: usize,
    pub total_urls_tested: usize,
    pub unique_urls_tested: usize,
    pub urls_per_role: HashMap<String, usize>,
}

// ============================================================================
// Builder Pattern for Easy Configuration
// ============================================================================

/// Builder for creating multi-role test configurations
pub struct MultiRoleBuilder {
    roles: Vec<UserRole>,
    config: MultiRoleConfig,
}

impl MultiRoleBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            roles: Vec::new(),
            config: MultiRoleConfig::default(),
        }
    }

    /// Add a role with credentials
    pub fn add_role(mut self, name: &str, username: &str, password: &str) -> Self {
        self.roles.push(UserRole::new(name, username, password));
        self
    }

    /// Add a guest role
    pub fn add_guest(mut self) -> Self {
        self.roles.push(UserRole::guest());
        self
    }

    /// Add an admin role
    pub fn add_admin(mut self, username: &str, password: &str) -> Self {
        let role = UserRole::new("admin", username, password)
            .with_permission_level(PermissionLevel::Admin)
            .with_description("Administrator account");
        self.roles.push(role);
        self
    }

    /// Add a custom role
    pub fn add_custom_role(mut self, role: UserRole) -> Self {
        self.roles.push(role);
        self
    }

    /// Set maximum concurrent browsers
    pub fn max_browsers(mut self, count: usize) -> Self {
        self.config.max_concurrent_browsers = count;
        self
    }

    /// Set browser timeout
    pub fn browser_timeout(mut self, secs: u64) -> Self {
        self.config.browser_timeout_secs = secs;
        self
    }

    /// Set maximum URLs per role
    pub fn max_urls(mut self, count: usize) -> Self {
        self.config.max_urls_per_role = count;
        self
    }

    /// Add mandatory test URLs
    pub fn test_urls(mut self, urls: Vec<String>) -> Self {
        self.config.mandatory_test_urls = urls;
        self
    }

    /// Enable/disable headless crawling
    pub fn headless(mut self, enabled: bool) -> Self {
        self.config.enable_headless_crawling = enabled;
        self
    }

    /// Set request delay
    pub fn request_delay(mut self, ms: u64) -> Self {
        self.config.request_delay_ms = ms;
        self
    }

    /// Build the orchestrator
    pub fn build(self, http_client: Arc<HttpClient>) -> (MultiRoleOrchestrator, Vec<UserRole>) {
        (
            MultiRoleOrchestrator::new(http_client, self.config),
            self.roles,
        )
    }
}

impl Default for MultiRoleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Quick setup for common two-role comparison (user vs admin)
pub async fn compare_user_admin(
    http_client: Arc<HttpClient>,
    base_url: &str,
    user_creds: (&str, &str),
    admin_creds: (&str, &str),
) -> Result<Vec<Vulnerability>> {
    let (orchestrator, roles) = MultiRoleBuilder::new()
        .add_role("user", user_creds.0, user_creds.1)
        .add_admin(admin_creds.0, admin_creds.1)
        .build(http_client);

    orchestrator.initialize_sessions(base_url, roles).await?;
    orchestrator.analyze_authorization(base_url).await
}

/// Quick setup for three-role comparison (guest, user, admin)
pub async fn compare_guest_user_admin(
    http_client: Arc<HttpClient>,
    base_url: &str,
    user_creds: (&str, &str),
    admin_creds: (&str, &str),
) -> Result<Vec<Vulnerability>> {
    let (orchestrator, roles) = MultiRoleBuilder::new()
        .add_guest()
        .add_role("user", user_creds.0, user_creds.1)
        .add_admin(admin_creds.0, admin_creds.1)
        .build(http_client);

    orchestrator.initialize_sessions(base_url, roles).await?;
    orchestrator.analyze_authorization(base_url).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_level_ordering() {
        assert!(PermissionLevel::Admin.is_higher_than(&PermissionLevel::User));
        assert!(PermissionLevel::User.is_higher_than(&PermissionLevel::Guest));
        assert!(PermissionLevel::SuperAdmin.is_higher_than(&PermissionLevel::Admin));
        assert!(PermissionLevel::Guest.is_lower_than(&PermissionLevel::User));
        assert!(!PermissionLevel::User.is_higher_than(&PermissionLevel::Admin));
    }

    #[test]
    fn test_permission_level_from_str() {
        assert_eq!(PermissionLevel::from_str("guest"), PermissionLevel::Guest);
        assert_eq!(PermissionLevel::from_str("ADMIN"), PermissionLevel::Admin);
        assert_eq!(PermissionLevel::from_str("superadmin"), PermissionLevel::SuperAdmin);
        assert_eq!(PermissionLevel::from_str("unknown"), PermissionLevel::User);
    }

    #[test]
    fn test_user_role_creation() {
        let role = UserRole::new("test_user", "user@example.com", "password123")
            .with_permission_level(PermissionLevel::User)
            .with_description("Test user account")
            .with_owned_resource("/api/users/123");

        assert_eq!(role.name, "test_user");
        assert_eq!(role.permission_level, PermissionLevel::User);
        assert!(role.owned_resources.contains("/api/users/123"));
        assert!(role.is_authenticated());
    }

    #[test]
    fn test_guest_role() {
        let guest = UserRole::guest();
        assert_eq!(guest.permission_level, PermissionLevel::Guest);
        assert!(!guest.is_authenticated());
    }

    #[test]
    fn test_response_metadata_user_data_detection() {
        let body_with_user_data = r#"{"email": "user@example.com", "name": "John"}"#;
        let body_without_user_data = r#"{"status": "ok"}"#;

        assert!(ResponseMetadata::detect_user_data(body_with_user_data));
        assert!(!ResponseMetadata::detect_user_data(body_without_user_data));
    }

    #[test]
    fn test_response_metadata_identifier_extraction() {
        let body = r#"{"userId": 12345, "email": "test@example.com", "uuid": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let identifiers = ResponseMetadata::extract_identifiers(body);

        assert!(identifiers.iter().any(|id| id.contains("12345")));
        assert!(identifiers.iter().any(|id| id.contains("test@example.com")));
        assert!(identifiers.iter().any(|id| id.contains("550e8400")));
    }

    #[test]
    fn test_access_result_display() {
        assert_eq!(format!("{}", AccessResult::Granted), "GRANTED");
        assert_eq!(format!("{}", AccessResult::Denied), "DENIED");
        assert_eq!(
            format!("{}", AccessResult::Redirect("/login".to_string())),
            "REDIRECT(/login)"
        );
        assert_eq!(format!("{}", AccessResult::Error(500)), "ERROR(500)");
    }

    #[test]
    fn test_role_comparison_creation() {
        let comparison = RoleComparison::new(
            "user",
            PermissionLevel::User,
            "admin",
            PermissionLevel::Admin,
        );

        assert_eq!(comparison.role_a, "user");
        assert_eq!(comparison.role_b, "admin");
        assert!(!comparison.has_findings());
    }

    #[test]
    fn test_multi_role_builder() {
        let builder = MultiRoleBuilder::new()
            .add_guest()
            .add_role("user", "user@test.com", "pass123")
            .add_admin("admin@test.com", "adminpass")
            .max_browsers(2)
            .max_urls(50);

        assert_eq!(builder.roles.len(), 3);
        assert_eq!(builder.config.max_concurrent_browsers, 2);
        assert_eq!(builder.config.max_urls_per_role, 50);
    }

    #[test]
    fn test_access_matrix_csv_export() {
        let matrix = AccessMatrix {
            roles: vec!["user".to_string(), "admin".to_string()],
            entries: vec![
                AccessMatrixEntry {
                    url: "/api/users".to_string(),
                    role_access: {
                        let mut map = HashMap::new();
                        map.insert("user".to_string(), AccessResult::Granted);
                        map.insert("admin".to_string(), AccessResult::Granted);
                        map
                    },
                },
                AccessMatrixEntry {
                    url: "/api/admin".to_string(),
                    role_access: {
                        let mut map = HashMap::new();
                        map.insert("user".to_string(), AccessResult::Denied);
                        map.insert("admin".to_string(), AccessResult::Granted);
                        map
                    },
                },
            ],
        };

        let csv = matrix.to_csv();
        assert!(csv.contains("URL,user,admin"));
        assert!(csv.contains("/api/users,GRANTED,GRANTED"));
        assert!(csv.contains("/api/admin,DENIED,GRANTED"));
    }

    #[test]
    fn test_escalation_type_display() {
        assert_eq!(format!("{}", EscalationType::Vertical), "Vertical");
        assert_eq!(format!("{}", EscalationType::Horizontal), "Horizontal");
        assert_eq!(format!("{}", EscalationType::Both), "Vertical+Horizontal");
    }

    #[test]
    fn test_sensitive_endpoint_detection() {
        let config = MultiRoleConfig::default();
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let orchestrator = MultiRoleOrchestrator::new(http_client, config);

        assert!(orchestrator.is_sensitive_admin_endpoint("/admin/users"));
        assert!(orchestrator.is_sensitive_admin_endpoint("/api/admin/settings"));
        assert!(orchestrator.is_sensitive_admin_endpoint("/dashboard"));
        assert!(!orchestrator.is_sensitive_admin_endpoint("/api/public/data"));
        assert!(!orchestrator.is_sensitive_admin_endpoint("/home"));
    }

    #[test]
    fn test_url_skip_patterns() {
        let config = MultiRoleConfig::default();
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let orchestrator = MultiRoleOrchestrator::new(http_client, config);

        assert!(orchestrator.should_skip_url("https://example.com/style.css"));
        assert!(orchestrator.should_skip_url("https://example.com/app.js"));
        assert!(orchestrator.should_skip_url("https://example.com/static/image.png"));
        assert!(!orchestrator.should_skip_url("https://example.com/api/users"));
        assert!(!orchestrator.should_skip_url("https://example.com/login"));
    }
}
