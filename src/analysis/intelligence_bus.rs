// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Intelligence Bus - Real-time scanner communication
//!
//! Allows scanners to share discoveries in real-time so other scanners
//! can adapt their testing strategies immediately.
//!
//! # Architecture
//!
//! The Intelligence Bus uses a publish-subscribe pattern with tokio's broadcast
//! channel for real-time event distribution. Key features:
//!
//! - **Real-time broadcasting**: Events are immediately sent to all subscribers
//! - **Accumulated state**: Late-joining scanners can access all previously discovered intelligence
//! - **Thread-safe**: Uses Arc and RwLock for safe concurrent access
//! - **Typed events**: Strongly typed events prevent miscommunication between scanners
//!
//! # Example
//!
//! ```rust,ignore
//! use lonkero::analysis::intelligence_bus::{IntelligenceBus, AuthType, IntelligenceEvent};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let bus = Arc::new(IntelligenceBus::new());
//!
//!     // Scanner A subscribes
//!     let mut rx = bus.subscribe();
//!
//!     // Scanner B reports a discovery
//!     bus.report_auth_type(AuthType::JWT, 0.95, "https://api.example.com/login").await;
//!
//!     // Scanner A receives the event
//!     if let Ok(event) = rx.recv().await {
//!         println!("Received: {:?}", event);
//!     }
//! }
//! ```

use std::fmt;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Default capacity for the broadcast channel
const CHANNEL_CAPACITY: usize = 1000;

/// Authentication types detected in the target application
#[derive(Debug, Clone, PartialEq)]
pub enum AuthType {
    /// JSON Web Token authentication
    JWT,
    /// OAuth 2.0 authentication
    OAuth2,
    /// Session-based authentication (cookies)
    Session,
    /// HTTP Basic authentication
    Basic,
    /// API Key authentication (header or query param)
    ApiKey,
    /// Bearer token (non-JWT)
    Bearer,
    /// SAML authentication
    SAML,
    /// OpenID Connect
    OIDC,
    /// Custom authentication scheme
    Custom(String),
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthType::JWT => write!(f, "JWT"),
            AuthType::OAuth2 => write!(f, "OAuth2"),
            AuthType::Session => write!(f, "Session"),
            AuthType::Basic => write!(f, "Basic"),
            AuthType::ApiKey => write!(f, "API Key"),
            AuthType::Bearer => write!(f, "Bearer"),
            AuthType::SAML => write!(f, "SAML"),
            AuthType::OIDC => write!(f, "OpenID Connect"),
            AuthType::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

/// Types of parameters that may be sensitive or exploitable
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterType {
    /// Identifier parameter (user_id, id, etc.)
    Id,
    /// Authentication-related parameter
    Auth,
    /// File path or name parameter
    File,
    /// URL parameter (redirect, callback, etc.)
    Url,
    /// Command or system execution parameter
    Command,
    /// Search query parameter
    Search,
    /// Email address parameter
    Email,
    /// Admin or privilege-related parameter
    Admin,
    /// Database query parameter
    Database,
    /// Template or format parameter
    Template,
    /// Numeric parameter
    Numeric,
    /// JSON or structured data parameter
    Json,
    /// Configuration parameter
    Config,
}

impl fmt::Display for ParameterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterType::Id => write!(f, "ID"),
            ParameterType::Auth => write!(f, "Auth"),
            ParameterType::File => write!(f, "File"),
            ParameterType::Url => write!(f, "URL"),
            ParameterType::Command => write!(f, "Command"),
            ParameterType::Search => write!(f, "Search"),
            ParameterType::Email => write!(f, "Email"),
            ParameterType::Admin => write!(f, "Admin"),
            ParameterType::Database => write!(f, "Database"),
            ParameterType::Template => write!(f, "Template"),
            ParameterType::Numeric => write!(f, "Numeric"),
            ParameterType::Json => write!(f, "JSON"),
            ParameterType::Config => write!(f, "Config"),
        }
    }
}

/// Types of vulnerability patterns detected
#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    /// SQL error message detected
    SqlError,
    /// File path disclosure
    PathDisclosure,
    /// Stack trace or debug output
    StackTrace,
    /// Version information leak
    VersionLeak,
    /// Internal IP address disclosure
    InternalIp,
    /// XML parsing error
    XmlError,
    /// JSON parsing error
    JsonError,
    /// Template engine error
    TemplateError,
    /// Command execution error
    CommandError,
    /// LDAP error
    LdapError,
    /// Authentication error details
    AuthError,
    /// Rate limiting response
    RateLimitResponse,
    /// Debug mode indicator
    DebugMode,
}

impl fmt::Display for PatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternType::SqlError => write!(f, "SQL Error"),
            PatternType::PathDisclosure => write!(f, "Path Disclosure"),
            PatternType::StackTrace => write!(f, "Stack Trace"),
            PatternType::VersionLeak => write!(f, "Version Leak"),
            PatternType::InternalIp => write!(f, "Internal IP"),
            PatternType::XmlError => write!(f, "XML Error"),
            PatternType::JsonError => write!(f, "JSON Error"),
            PatternType::TemplateError => write!(f, "Template Error"),
            PatternType::CommandError => write!(f, "Command Error"),
            PatternType::LdapError => write!(f, "LDAP Error"),
            PatternType::AuthError => write!(f, "Auth Error"),
            PatternType::RateLimitResponse => write!(f, "Rate Limit"),
            PatternType::DebugMode => write!(f, "Debug Mode"),
        }
    }
}

/// Types of endpoint patterns detected
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointPatternType {
    /// RESTful CRUD endpoints
    RestCrud,
    /// GraphQL endpoint
    GraphQL,
    /// JSON-RPC endpoint
    JsonRpc,
    /// API versioning pattern (v1, v2, etc.)
    ApiVersioning,
    /// Internal/admin API endpoints
    InternalApi,
    /// Batch/bulk operation endpoints
    BatchApi,
    /// WebSocket endpoints
    WebSocket,
    /// Server-Sent Events endpoints
    ServerSentEvents,
    /// gRPC endpoints
    GRPC,
    /// Legacy/deprecated endpoints
    LegacyApi,
    /// Health check endpoints
    HealthCheck,
    /// Metrics/monitoring endpoints
    Metrics,
}

impl fmt::Display for EndpointPatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointPatternType::RestCrud => write!(f, "REST CRUD"),
            EndpointPatternType::GraphQL => write!(f, "GraphQL"),
            EndpointPatternType::JsonRpc => write!(f, "JSON-RPC"),
            EndpointPatternType::ApiVersioning => write!(f, "API Versioning"),
            EndpointPatternType::InternalApi => write!(f, "Internal API"),
            EndpointPatternType::BatchApi => write!(f, "Batch API"),
            EndpointPatternType::WebSocket => write!(f, "WebSocket"),
            EndpointPatternType::ServerSentEvents => write!(f, "SSE"),
            EndpointPatternType::GRPC => write!(f, "gRPC"),
            EndpointPatternType::LegacyApi => write!(f, "Legacy API"),
            EndpointPatternType::HealthCheck => write!(f, "Health Check"),
            EndpointPatternType::Metrics => write!(f, "Metrics"),
        }
    }
}

/// Types of insights scanners can share
#[derive(Debug, Clone, PartialEq)]
pub enum InsightType {
    /// A security bypass was found
    BypassFound,
    /// Weak input validation detected
    WeakValidation,
    /// Missing authentication on endpoint
    MissingAuth,
    /// Rate limiting can be bypassed
    RateLimitBypass,
    /// Cache control issues
    CacheControl,
    /// CORS misconfiguration
    CorsMisconfig,
    /// Session handling weakness
    SessionWeakness,
    /// Privilege escalation possibility
    PrivilegeEscalation,
    /// Information disclosure
    InfoDisclosure,
    /// Injection point found
    InjectionPoint,
}

impl fmt::Display for InsightType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsightType::BypassFound => write!(f, "Bypass Found"),
            InsightType::WeakValidation => write!(f, "Weak Validation"),
            InsightType::MissingAuth => write!(f, "Missing Auth"),
            InsightType::RateLimitBypass => write!(f, "Rate Limit Bypass"),
            InsightType::CacheControl => write!(f, "Cache Control"),
            InsightType::CorsMisconfig => write!(f, "CORS Misconfiguration"),
            InsightType::SessionWeakness => write!(f, "Session Weakness"),
            InsightType::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            InsightType::InfoDisclosure => write!(f, "Info Disclosure"),
            InsightType::InjectionPoint => write!(f, "Injection Point"),
        }
    }
}

/// Events that can be broadcast through the Intelligence Bus
#[derive(Debug, Clone)]
pub enum IntelligenceEvent {
    /// Authentication type detected on the target
    AuthTypeDetected {
        auth_type: AuthType,
        confidence: f32,
        source_url: String,
    },

    /// Framework or technology detected
    FrameworkDetected {
        name: String,
        version: Option<String>,
        confidence: f32,
    },

    /// Sensitive parameter found
    SensitiveParameterFound {
        param_name: String,
        param_type: ParameterType,
        endpoint: String,
    },

    /// Vulnerability pattern detected
    VulnerabilityPattern {
        pattern_type: PatternType,
        evidence: String,
        endpoint: Option<String>,
    },

    /// Web Application Firewall detected
    WafDetected {
        waf_type: String,
        bypass_hints: Vec<String>,
    },

    /// Endpoint pattern identified
    EndpointPattern {
        pattern: EndpointPatternType,
        examples: Vec<String>,
    },

    /// Technology stack update
    TechStackUpdate {
        technologies: Vec<String>,
    },

    /// Scanner-specific insight
    ScannerInsight {
        scanner_name: String,
        insight_type: InsightType,
        data: String,
    },

    /// Custom event for extensibility
    Custom {
        event_type: String,
        data: String,
    },
}

impl fmt::Display for IntelligenceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntelligenceEvent::AuthTypeDetected {
                auth_type,
                confidence,
                source_url,
            } => {
                write!(
                    f,
                    "Auth Detected: {} (confidence: {:.0}%) from {}",
                    auth_type,
                    confidence * 100.0,
                    source_url
                )
            }
            IntelligenceEvent::FrameworkDetected {
                name,
                version,
                confidence,
            } => {
                let ver = version.as_deref().unwrap_or("unknown");
                write!(
                    f,
                    "Framework: {} v{} (confidence: {:.0}%)",
                    name,
                    ver,
                    confidence * 100.0
                )
            }
            IntelligenceEvent::SensitiveParameterFound {
                param_name,
                param_type,
                endpoint,
            } => {
                write!(
                    f,
                    "Sensitive Param: {} ({}) at {}",
                    param_name, param_type, endpoint
                )
            }
            IntelligenceEvent::VulnerabilityPattern {
                pattern_type,
                evidence,
                endpoint,
            } => {
                let ep = endpoint.as_deref().unwrap_or("unknown");
                write!(
                    f,
                    "Vuln Pattern: {} at {} - {}",
                    pattern_type,
                    ep,
                    &evidence[..evidence.len().min(50)]
                )
            }
            IntelligenceEvent::WafDetected {
                waf_type,
                bypass_hints,
            } => {
                write!(
                    f,
                    "WAF Detected: {} ({} bypass hints)",
                    waf_type,
                    bypass_hints.len()
                )
            }
            IntelligenceEvent::EndpointPattern { pattern, examples } => {
                write!(f, "Endpoint Pattern: {} ({} examples)", pattern, examples.len())
            }
            IntelligenceEvent::TechStackUpdate { technologies } => {
                write!(f, "Tech Stack: {}", technologies.join(", "))
            }
            IntelligenceEvent::ScannerInsight {
                scanner_name,
                insight_type,
                data,
            } => {
                write!(f, "Insight from {}: {} - {}", scanner_name, insight_type, data)
            }
            IntelligenceEvent::Custom { event_type, data } => {
                write!(f, "Custom Event: {} - {}", event_type, data)
            }
        }
    }
}

/// Accumulated intelligence from all events
///
/// This structure stores all intelligence gathered during a scan,
/// allowing late-joining scanners to access previously discovered information.
#[derive(Debug, Default, Clone)]
pub struct AccumulatedIntelligence {
    /// Detected authentication types with confidence scores
    pub auth_types: Vec<(AuthType, f32, String)>,
    /// Detected frameworks with versions and confidence
    pub frameworks: Vec<(String, Option<String>, f32)>,
    /// Sensitive parameters found
    pub sensitive_params: Vec<(String, ParameterType, String)>,
    /// WAF information if detected
    pub waf_info: Option<(String, Vec<String>)>,
    /// Endpoint patterns identified
    pub endpoint_patterns: Vec<(EndpointPatternType, Vec<String>)>,
    /// Technology stack
    pub tech_stack: Vec<String>,
    /// Vulnerability patterns found
    pub vulnerability_patterns: Vec<(PatternType, String)>,
    /// Scanner insights
    pub insights: Vec<(String, InsightType, String)>,
}

impl AccumulatedIntelligence {
    /// Create a new empty accumulated intelligence store
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the primary authentication type (highest confidence)
    pub fn primary_auth_type(&self) -> Option<&AuthType> {
        self.auth_types
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(auth, _, _)| auth)
    }

    /// Check if a specific framework is detected
    pub fn has_framework(&self, name: &str) -> bool {
        self.frameworks
            .iter()
            .any(|(n, _, _)| n.to_lowercase() == name.to_lowercase())
    }

    /// Check if WAF is detected
    pub fn has_waf(&self) -> bool {
        self.waf_info.is_some()
    }

    /// Get WAF bypass hints if available
    pub fn waf_bypass_hints(&self) -> Vec<String> {
        self.waf_info
            .as_ref()
            .map(|(_, hints)| hints.clone())
            .unwrap_or_default()
    }

    /// Check if a technology is in the stack
    pub fn has_technology(&self, tech: &str) -> bool {
        self.tech_stack
            .iter()
            .any(|t| t.to_lowercase().contains(&tech.to_lowercase()))
    }

    /// Get all sensitive parameters of a specific type
    pub fn params_of_type(&self, param_type: &ParameterType) -> Vec<&str> {
        self.sensitive_params
            .iter()
            .filter(|(_, pt, _)| pt == param_type)
            .map(|(name, _, _)| name.as_str())
            .collect()
    }

    /// Check if any vulnerability patterns were found
    pub fn has_vulnerability_patterns(&self) -> bool {
        !self.vulnerability_patterns.is_empty()
    }

    /// Get insights from a specific scanner
    pub fn insights_from(&self, scanner_name: &str) -> Vec<(&InsightType, &str)> {
        self.insights
            .iter()
            .filter(|(name, _, _)| name == scanner_name)
            .map(|(_, insight_type, data)| (insight_type, data.as_str()))
            .collect()
    }
}

/// The Intelligence Bus for real-time scanner communication
///
/// This is the central hub for scanner-to-scanner communication.
/// Scanners can broadcast discoveries and subscribe to updates from other scanners.
pub struct IntelligenceBus {
    /// Broadcast sender for real-time events
    sender: broadcast::Sender<IntelligenceEvent>,
    /// Accumulated intelligence for late-joining scanners
    accumulated: Arc<RwLock<AccumulatedIntelligence>>,
    /// Event counter for statistics
    event_count: Arc<std::sync::atomic::AtomicU64>,
}

impl Default for IntelligenceBus {
    fn default() -> Self {
        Self::new()
    }
}

impl IntelligenceBus {
    /// Create a new Intelligence Bus
    ///
    /// Initializes the broadcast channel with default capacity and
    /// an empty accumulated intelligence store.
    pub fn new() -> Self {
        Self::with_capacity(CHANNEL_CAPACITY)
    }

    /// Create a new Intelligence Bus with custom channel capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            accumulated: Arc::new(RwLock::new(AccumulatedIntelligence::new())),
            event_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Subscribe to intelligence events
    ///
    /// Returns a receiver that will receive all future events.
    /// Use `get_accumulated()` to get events that occurred before subscribing.
    pub fn subscribe(&self) -> broadcast::Receiver<IntelligenceEvent> {
        self.sender.subscribe()
    }

    /// Get the number of current subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Get the total number of events broadcast
    pub fn event_count(&self) -> u64 {
        self.event_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Broadcast an intelligence event
    ///
    /// Sends the event to all subscribers and updates the accumulated intelligence.
    pub async fn broadcast(&self, event: IntelligenceEvent) {
        // Update accumulated intelligence
        self.update_accumulated(&event).await;

        // Increment event counter
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Send to subscribers
        let receiver_count = self.sender.receiver_count();
        if receiver_count > 0 {
            match self.sender.send(event.clone()) {
                Ok(count) => {
                    debug!("Broadcast intelligence event to {} receivers: {}", count, event);
                }
                Err(e) => {
                    warn!("Failed to broadcast intelligence event: {}", e);
                }
            }
        } else {
            debug!("No subscribers for intelligence event: {}", event);
        }
    }

    /// Update accumulated intelligence based on event
    async fn update_accumulated(&self, event: &IntelligenceEvent) {
        let mut accumulated = self.accumulated.write().await;

        match event {
            IntelligenceEvent::AuthTypeDetected {
                auth_type,
                confidence,
                source_url,
            } => {
                // Check if we already have this auth type
                let exists = accumulated
                    .auth_types
                    .iter()
                    .any(|(at, _, _)| at == auth_type);
                if !exists {
                    accumulated.auth_types.push((
                        auth_type.clone(),
                        *confidence,
                        source_url.clone(),
                    ));
                    info!("Intelligence: {} detected with {:.0}% confidence", auth_type, confidence * 100.0);
                }
            }
            IntelligenceEvent::FrameworkDetected {
                name,
                version,
                confidence,
            } => {
                let exists = accumulated
                    .frameworks
                    .iter()
                    .any(|(n, _, _)| n.to_lowercase() == name.to_lowercase());
                if !exists {
                    accumulated
                        .frameworks
                        .push((name.clone(), version.clone(), *confidence));
                    info!(
                        "Intelligence: Framework {} {:?} detected with {:.0}% confidence",
                        name,
                        version,
                        confidence * 100.0
                    );
                }
            }
            IntelligenceEvent::SensitiveParameterFound {
                param_name,
                param_type,
                endpoint,
            } => {
                let exists = accumulated
                    .sensitive_params
                    .iter()
                    .any(|(n, _, e)| n == param_name && e == endpoint);
                if !exists {
                    accumulated.sensitive_params.push((
                        param_name.clone(),
                        param_type.clone(),
                        endpoint.clone(),
                    ));
                    debug!(
                        "Intelligence: Sensitive parameter {} ({}) found at {}",
                        param_name, param_type, endpoint
                    );
                }
            }
            IntelligenceEvent::VulnerabilityPattern {
                pattern_type,
                evidence,
                ..
            } => {
                accumulated
                    .vulnerability_patterns
                    .push((pattern_type.clone(), evidence.clone()));
                info!("Intelligence: {} pattern detected", pattern_type);
            }
            IntelligenceEvent::WafDetected {
                waf_type,
                bypass_hints,
            } => {
                if accumulated.waf_info.is_none() {
                    accumulated.waf_info = Some((waf_type.clone(), bypass_hints.clone()));
                    info!(
                        "Intelligence: WAF {} detected with {} bypass hints",
                        waf_type,
                        bypass_hints.len()
                    );
                } else if let Some((_, ref mut hints)) = accumulated.waf_info {
                    // Merge bypass hints
                    for hint in bypass_hints {
                        if !hints.contains(hint) {
                            hints.push(hint.clone());
                        }
                    }
                }
            }
            IntelligenceEvent::EndpointPattern { pattern, examples } => {
                let exists = accumulated
                    .endpoint_patterns
                    .iter()
                    .any(|(p, _)| p == pattern);
                if !exists {
                    accumulated
                        .endpoint_patterns
                        .push((pattern.clone(), examples.clone()));
                    debug!("Intelligence: {} endpoint pattern detected", pattern);
                }
            }
            IntelligenceEvent::TechStackUpdate { technologies } => {
                for tech in technologies {
                    if !accumulated.tech_stack.contains(tech) {
                        accumulated.tech_stack.push(tech.clone());
                        debug!("Intelligence: Technology {} added to stack", tech);
                    }
                }
            }
            IntelligenceEvent::ScannerInsight {
                scanner_name,
                insight_type,
                data,
            } => {
                accumulated.insights.push((
                    scanner_name.clone(),
                    insight_type.clone(),
                    data.clone(),
                ));
                info!(
                    "Intelligence: {} reported {} - {}",
                    scanner_name, insight_type, data
                );
            }
            IntelligenceEvent::Custom { event_type, data } => {
                debug!("Intelligence: Custom event {} - {}", event_type, data);
            }
        }
    }

    /// Get accumulated intelligence
    ///
    /// Returns a clone of all accumulated intelligence gathered so far.
    /// Useful for scanners that start later in the scan process.
    pub async fn get_accumulated(&self) -> AccumulatedIntelligence {
        self.accumulated.read().await.clone()
    }

    /// Clear accumulated intelligence
    ///
    /// Resets the accumulated intelligence store. Useful for starting a new scan.
    pub async fn clear(&self) {
        let mut accumulated = self.accumulated.write().await;
        *accumulated = AccumulatedIntelligence::new();
        self.event_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        info!("Intelligence Bus cleared");
    }

    // ============ Convenience methods for common broadcasts ============

    /// Report authentication type detection
    pub async fn report_auth_type(&self, auth_type: AuthType, confidence: f32, source: &str) {
        self.broadcast(IntelligenceEvent::AuthTypeDetected {
            auth_type,
            confidence: confidence.clamp(0.0, 1.0),
            source_url: source.to_string(),
        })
        .await;
    }

    /// Report framework detection
    pub async fn report_framework(&self, name: &str, version: Option<&str>, confidence: f32) {
        self.broadcast(IntelligenceEvent::FrameworkDetected {
            name: name.to_string(),
            version: version.map(String::from),
            confidence: confidence.clamp(0.0, 1.0),
        })
        .await;
    }

    /// Report WAF detection
    pub async fn report_waf(&self, waf_type: &str, bypass_hints: Vec<String>) {
        self.broadcast(IntelligenceEvent::WafDetected {
            waf_type: waf_type.to_string(),
            bypass_hints,
        })
        .await;
    }

    /// Report sensitive parameter discovery
    pub async fn report_sensitive_param(
        &self,
        name: &str,
        param_type: ParameterType,
        endpoint: &str,
    ) {
        self.broadcast(IntelligenceEvent::SensitiveParameterFound {
            param_name: name.to_string(),
            param_type,
            endpoint: endpoint.to_string(),
        })
        .await;
    }

    /// Report vulnerability pattern
    pub async fn report_vulnerability_pattern(
        &self,
        pattern_type: PatternType,
        evidence: &str,
        endpoint: Option<&str>,
    ) {
        self.broadcast(IntelligenceEvent::VulnerabilityPattern {
            pattern_type,
            evidence: evidence.to_string(),
            endpoint: endpoint.map(String::from),
        })
        .await;
    }

    /// Report endpoint pattern
    pub async fn report_endpoint_pattern(
        &self,
        pattern: EndpointPatternType,
        examples: Vec<String>,
    ) {
        self.broadcast(IntelligenceEvent::EndpointPattern { pattern, examples })
            .await;
    }

    /// Report technology stack update
    pub async fn report_tech_stack(&self, technologies: Vec<String>) {
        self.broadcast(IntelligenceEvent::TechStackUpdate { technologies })
            .await;
    }

    /// Report scanner insight
    pub async fn report_insight(
        &self,
        scanner_name: &str,
        insight_type: InsightType,
        data: &str,
    ) {
        self.broadcast(IntelligenceEvent::ScannerInsight {
            scanner_name: scanner_name.to_string(),
            insight_type,
            data: data.to_string(),
        })
        .await;
    }

    /// Report custom event
    pub async fn report_custom(&self, event_type: &str, data: &str) {
        self.broadcast(IntelligenceEvent::Custom {
            event_type: event_type.to_string(),
            data: data.to_string(),
        })
        .await;
    }
}

/// Trait for scanners that can receive and react to intelligence events
pub trait IntelligenceAware: Send + Sync {
    /// Handle an incoming intelligence event
    ///
    /// Implement this method to react to events from other scanners.
    fn on_intelligence(&mut self, event: &IntelligenceEvent);

    /// Get the intelligence bus if available
    fn get_bus(&self) -> Option<Arc<IntelligenceBus>>;

    /// Set the intelligence bus
    fn set_bus(&mut self, bus: Arc<IntelligenceBus>);
}

/// A simple subscriber that collects events
///
/// Useful for testing and debugging.
pub struct IntelligenceCollector {
    bus: Arc<IntelligenceBus>,
    events: Arc<RwLock<Vec<IntelligenceEvent>>>,
}

impl IntelligenceCollector {
    /// Create a new collector attached to a bus
    pub fn new(bus: Arc<IntelligenceBus>) -> Self {
        Self {
            bus,
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start collecting events in the background
    pub fn start_collecting(&self) -> tokio::task::JoinHandle<()> {
        let mut rx = self.bus.subscribe();
        let events = self.events.clone();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        events.write().await.push(event);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        warn!("Collector lagged by {} events", count);
                    }
                }
            }
        })
    }

    /// Get all collected events
    pub async fn get_events(&self) -> Vec<IntelligenceEvent> {
        self.events.read().await.clone()
    }

    /// Clear collected events
    pub async fn clear(&self) {
        self.events.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_bus_creation() {
        let bus = IntelligenceBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.event_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_and_receive() {
        let bus = Arc::new(IntelligenceBus::new());
        let mut rx = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 1);

        bus.report_auth_type(AuthType::JWT, 0.95, "https://example.com")
            .await;

        let event = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Failed to receive event");

        match event {
            IntelligenceEvent::AuthTypeDetected {
                auth_type,
                confidence,
                source_url,
            } => {
                assert_eq!(auth_type, AuthType::JWT);
                assert!((confidence - 0.95).abs() < f32::EPSILON);
                assert_eq!(source_url, "https://example.com");
            }
            _ => panic!("Unexpected event type"),
        }
    }

    #[tokio::test]
    async fn test_accumulated_intelligence() {
        let bus = IntelligenceBus::new();

        // Broadcast some events
        bus.report_auth_type(AuthType::JWT, 0.95, "https://api.example.com")
            .await;
        bus.report_framework("Django", Some("4.2"), 0.9).await;
        bus.report_waf(
            "Cloudflare",
            vec!["Use case variation".to_string()],
        )
        .await;

        // Check accumulated intelligence
        let accumulated = bus.get_accumulated().await;

        assert_eq!(accumulated.auth_types.len(), 1);
        assert_eq!(accumulated.auth_types[0].0, AuthType::JWT);

        assert_eq!(accumulated.frameworks.len(), 1);
        assert_eq!(accumulated.frameworks[0].0, "Django");
        assert_eq!(accumulated.frameworks[0].1, Some("4.2".to_string()));

        assert!(accumulated.has_waf());
        assert!(accumulated.has_framework("django"));
    }

    #[tokio::test]
    async fn test_sensitive_parameter_detection() {
        let bus = IntelligenceBus::new();

        bus.report_sensitive_param("user_id", ParameterType::Id, "/api/users")
            .await;
        bus.report_sensitive_param("admin", ParameterType::Admin, "/api/settings")
            .await;
        bus.report_sensitive_param("file", ParameterType::File, "/api/upload")
            .await;

        let accumulated = bus.get_accumulated().await;
        assert_eq!(accumulated.sensitive_params.len(), 3);

        let id_params = accumulated.params_of_type(&ParameterType::Id);
        assert_eq!(id_params.len(), 1);
        assert_eq!(id_params[0], "user_id");
    }

    #[tokio::test]
    async fn test_vulnerability_pattern() {
        let bus = IntelligenceBus::new();

        bus.report_vulnerability_pattern(
            PatternType::SqlError,
            "You have an error in your SQL syntax",
            Some("/api/search"),
        )
        .await;

        let accumulated = bus.get_accumulated().await;
        assert!(accumulated.has_vulnerability_patterns());
        assert_eq!(accumulated.vulnerability_patterns.len(), 1);
    }

    #[tokio::test]
    async fn test_endpoint_pattern() {
        let bus = IntelligenceBus::new();

        bus.report_endpoint_pattern(
            EndpointPatternType::RestCrud,
            vec![
                "/api/users".to_string(),
                "/api/products".to_string(),
            ],
        )
        .await;

        let accumulated = bus.get_accumulated().await;
        assert_eq!(accumulated.endpoint_patterns.len(), 1);
        assert_eq!(accumulated.endpoint_patterns[0].0, EndpointPatternType::RestCrud);
    }

    #[tokio::test]
    async fn test_tech_stack_update() {
        let bus = IntelligenceBus::new();

        bus.report_tech_stack(vec![
            "Python".to_string(),
            "PostgreSQL".to_string(),
            "Redis".to_string(),
        ])
        .await;

        let accumulated = bus.get_accumulated().await;
        assert!(accumulated.has_technology("python"));
        assert!(accumulated.has_technology("redis"));
        assert!(!accumulated.has_technology("mysql"));
    }

    #[tokio::test]
    async fn test_scanner_insight() {
        let bus = IntelligenceBus::new();

        bus.report_insight(
            "auth_bypass_scanner",
            InsightType::BypassFound,
            "Role parameter can be manipulated",
        )
        .await;

        let accumulated = bus.get_accumulated().await;
        let insights = accumulated.insights_from("auth_bypass_scanner");
        assert_eq!(insights.len(), 1);
        assert_eq!(*insights[0].0, InsightType::BypassFound);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = Arc::new(IntelligenceBus::new());
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 2);

        bus.report_framework("Express", Some("4.18"), 0.85).await;

        let event1 = timeout(Duration::from_millis(100), rx1.recv())
            .await
            .expect("Timeout")
            .expect("Failed to receive");
        let event2 = timeout(Duration::from_millis(100), rx2.recv())
            .await
            .expect("Timeout")
            .expect("Failed to receive");

        // Both should receive the same event
        match (&event1, &event2) {
            (
                IntelligenceEvent::FrameworkDetected { name: n1, .. },
                IntelligenceEvent::FrameworkDetected { name: n2, .. },
            ) => {
                assert_eq!(n1, "Express");
                assert_eq!(n2, "Express");
            }
            _ => panic!("Unexpected event types"),
        }
    }

    #[tokio::test]
    async fn test_clear_accumulated() {
        let bus = IntelligenceBus::new();

        bus.report_auth_type(AuthType::Session, 0.8, "https://example.com")
            .await;

        let accumulated = bus.get_accumulated().await;
        assert_eq!(accumulated.auth_types.len(), 1);

        bus.clear().await;

        let accumulated = bus.get_accumulated().await;
        assert_eq!(accumulated.auth_types.len(), 0);
        assert_eq!(bus.event_count(), 0);
    }

    #[tokio::test]
    async fn test_confidence_clamping() {
        let bus = IntelligenceBus::new();

        // Test that confidence is clamped to [0, 1]
        bus.report_auth_type(AuthType::JWT, 1.5, "https://example.com")
            .await;
        bus.report_framework("Rails", None, -0.5).await;

        let accumulated = bus.get_accumulated().await;
        assert!((accumulated.auth_types[0].1 - 1.0).abs() < f32::EPSILON);
        assert!(accumulated.frameworks[0].2.abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_no_duplicate_frameworks() {
        let bus = IntelligenceBus::new();

        bus.report_framework("Django", Some("4.2"), 0.9).await;
        bus.report_framework("django", Some("4.2"), 0.85).await; // Same framework, different case
        bus.report_framework("DJANGO", Some("4.3"), 0.95).await; // Same framework, different case

        let accumulated = bus.get_accumulated().await;
        assert_eq!(accumulated.frameworks.len(), 1); // Should only have one entry
    }

    #[tokio::test]
    async fn test_waf_bypass_hints_merge() {
        let bus = IntelligenceBus::new();

        bus.report_waf("ModSecurity", vec!["Hint 1".to_string()])
            .await;
        bus.report_waf(
            "ModSecurity",
            vec!["Hint 2".to_string(), "Hint 3".to_string()],
        )
        .await;

        let accumulated = bus.get_accumulated().await;
        let hints = accumulated.waf_bypass_hints();
        assert_eq!(hints.len(), 3);
        assert!(hints.contains(&"Hint 1".to_string()));
        assert!(hints.contains(&"Hint 2".to_string()));
        assert!(hints.contains(&"Hint 3".to_string()));
    }

    #[tokio::test]
    async fn test_primary_auth_type() {
        let bus = IntelligenceBus::new();

        bus.report_auth_type(AuthType::Session, 0.6, "https://example.com/login")
            .await;
        bus.report_auth_type(AuthType::JWT, 0.95, "https://example.com/api")
            .await;
        bus.report_auth_type(AuthType::ApiKey, 0.3, "https://example.com/public")
            .await;

        let accumulated = bus.get_accumulated().await;
        let primary = accumulated.primary_auth_type();
        assert_eq!(primary, Some(&AuthType::JWT));
    }

    #[tokio::test]
    async fn test_event_display() {
        let event = IntelligenceEvent::AuthTypeDetected {
            auth_type: AuthType::JWT,
            confidence: 0.95,
            source_url: "https://api.example.com".to_string(),
        };
        let display = format!("{}", event);
        assert!(display.contains("JWT"));
        assert!(display.contains("95%"));
    }

    #[tokio::test]
    async fn test_collector() {
        let bus = Arc::new(IntelligenceBus::new());
        let collector = IntelligenceCollector::new(bus.clone());
        let handle = collector.start_collecting();

        // Give collector time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        bus.report_auth_type(AuthType::OAuth2, 0.8, "https://oauth.example.com")
            .await;
        bus.report_framework("FastAPI", Some("0.100"), 0.9).await;

        // Give events time to propagate
        tokio::time::sleep(Duration::from_millis(50)).await;

        let events = collector.get_events().await;
        assert_eq!(events.len(), 2);

        handle.abort();
    }

    #[tokio::test]
    async fn test_event_count() {
        let bus = IntelligenceBus::new();

        bus.report_auth_type(AuthType::Basic, 0.5, "https://example.com")
            .await;
        bus.report_framework("Flask", None, 0.7).await;
        bus.report_tech_stack(vec!["Python".to_string()]).await;

        assert_eq!(bus.event_count(), 3);
    }

    #[tokio::test]
    async fn test_custom_event() {
        let bus = IntelligenceBus::new();
        let mut rx = bus.subscribe();

        bus.report_custom("rate_limit_info", "1000 requests per minute")
            .await;

        let event = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("Timeout")
            .expect("Failed to receive");

        match event {
            IntelligenceEvent::Custom { event_type, data } => {
                assert_eq!(event_type, "rate_limit_info");
                assert_eq!(data, "1000 requests per minute");
            }
            _ => panic!("Unexpected event type"),
        }
    }

    #[test]
    fn test_auth_type_display() {
        assert_eq!(format!("{}", AuthType::JWT), "JWT");
        assert_eq!(format!("{}", AuthType::OAuth2), "OAuth2");
        assert_eq!(format!("{}", AuthType::Custom("HMAC".to_string())), "Custom(HMAC)");
    }

    #[test]
    fn test_parameter_type_display() {
        assert_eq!(format!("{}", ParameterType::Id), "ID");
        assert_eq!(format!("{}", ParameterType::Command), "Command");
    }

    #[test]
    fn test_pattern_type_display() {
        assert_eq!(format!("{}", PatternType::SqlError), "SQL Error");
        assert_eq!(format!("{}", PatternType::StackTrace), "Stack Trace");
    }

    #[test]
    fn test_endpoint_pattern_type_display() {
        assert_eq!(format!("{}", EndpointPatternType::RestCrud), "REST CRUD");
        assert_eq!(format!("{}", EndpointPatternType::GraphQL), "GraphQL");
    }

    #[test]
    fn test_insight_type_display() {
        assert_eq!(format!("{}", InsightType::BypassFound), "Bypass Found");
        assert_eq!(format!("{}", InsightType::WeakValidation), "Weak Validation");
    }
}
