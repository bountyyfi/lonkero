// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Session Recording Module for Browser Session Capture and Replay
//!
//! This module provides comprehensive session recording capabilities for the
//! headless browser crawler, enabling:
//! - Full network request/response capture in HAR format
//! - DOM interaction recording (clicks, form submissions, scrolls)
//! - Console message and error capture
//! - Screenshot capture at key points
//! - Session replay for debugging vulnerabilities
//!
//! # Example
//!
//! ```rust,ignore
//! use lonkero_scanner::session_recording::{SessionRecorder, SessionExporter, ExportFormat};
//!
//! // Create a recorder
//! let recorder = SessionRecorder::new();
//! recorder.start();
//!
//! // Record events during crawl...
//! recorder.record_navigation("https://example.com".to_string());
//! recorder.record_network_request(request_event);
//!
//! // Export the recording
//! let recording = recorder.stop();
//! let exporter = SessionExporter::new(&recording);
//! let har = exporter.export(ExportFormat::Har)?;
//! ```

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};

// ============================================================================
// Core Types
// ============================================================================

/// Type of session event captured during recording
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEventType {
    /// Page navigation (URL change)
    Navigation,
    /// Network request initiated
    NetworkRequest,
    /// Network response received
    NetworkResponse,
    /// Network request failed
    NetworkError,
    /// DOM click event
    Click,
    /// Form field input
    Input,
    /// Form submission
    FormSubmit,
    /// Page scroll
    Scroll,
    /// Console message
    ConsoleMessage,
    /// JavaScript error
    JsError,
    /// Screenshot captured
    Screenshot,
    /// Cookie set/modified
    CookieChange,
    /// Local/session storage change
    StorageChange,
    /// WebSocket message
    WebSocketMessage,
    /// Custom marker event (for debugging)
    Marker,
}

/// Severity level for console messages and errors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleSeverity {
    Log,
    Info,
    Warning,
    Error,
    Debug,
}

/// HTTP method for network requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Connect,
    Trace,
    /// Unknown HTTP method - preserves the original method string
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Connect => write!(f, "CONNECT"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "CONNECT" => HttpMethod::Connect,
            "TRACE" => HttpMethod::Trace,
            other => {
                debug!("Unknown HTTP method encountered: {}", other);
                HttpMethod::Unknown
            }
        }
    }
}

/// Network request details captured during recording
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {
    /// Unique request ID for correlation with response
    pub request_id: String,
    /// Request URL
    pub url: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Content-Type of request body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Size of request in bytes
    pub size: usize,
    /// Timestamp when request was initiated
    pub timestamp: DateTime<Utc>,
    /// Initiator type (script, link, fetch, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator: Option<String>,
    /// Stack trace of request origin (for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
}

/// Network response details captured during recording
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// HTTP status code
    pub status_code: u16,
    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (may be truncated for large responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Whether body was truncated
    pub body_truncated: bool,
    /// Content-Type of response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Size of response in bytes
    pub size: usize,
    /// Time to first byte (ms)
    pub ttfb_ms: u64,
    /// Total response time (ms)
    pub duration_ms: u64,
    /// Timestamp when response was received
    pub timestamp: DateTime<Utc>,
    /// Whether response came from cache
    pub from_cache: bool,
}

/// Network error details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkError {
    /// Request ID for correlation
    pub request_id: String,
    /// Error type (dns, connection, timeout, etc.)
    pub error_type: String,
    /// Error message
    pub message: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// DOM interaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomInteraction {
    /// Type of interaction
    pub interaction_type: DomInteractionType,
    /// CSS selector of target element
    pub selector: String,
    /// XPath of target element (for precise replay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpath: Option<String>,
    /// Element tag name
    pub tag_name: String,
    /// Element ID (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element_id: Option<String>,
    /// Element classes
    #[serde(default)]
    pub classes: Vec<String>,
    /// Element text content (truncated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_content: Option<String>,
    /// Input value (for input events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_value: Option<String>,
    /// Scroll position (for scroll events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scroll_position: Option<ScrollPosition>,
    /// Click coordinates (for click events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<ClickCoordinates>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Type of DOM interaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomInteractionType {
    Click,
    DoubleClick,
    RightClick,
    Input,
    Focus,
    Blur,
    Submit,
    Scroll,
    Hover,
    KeyPress,
}

/// Scroll position details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrollPosition {
    pub x: i32,
    pub y: i32,
    pub max_x: i32,
    pub max_y: i32,
}

/// Click coordinates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClickCoordinates {
    pub x: i32,
    pub y: i32,
    pub viewport_x: i32,
    pub viewport_y: i32,
}

/// Console message details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleMessage {
    /// Message severity level
    pub severity: ConsoleSeverity,
    /// Message text
    pub text: String,
    /// Source URL where message originated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// Line number in source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// Column number in source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_number: Option<u32>,
    /// Stack trace (for errors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Screenshot captured during recording
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Screenshot {
    /// Unique screenshot ID
    pub id: String,
    /// Base64-encoded PNG image data
    pub data: String,
    /// Image format (always "png")
    pub format: String,
    /// Image width
    pub width: u32,
    /// Image height
    pub height: u32,
    /// Description/context for the screenshot
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// URL at time of capture
    pub url: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Navigation event details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigationEvent {
    /// Navigation URL
    pub url: String,
    /// Previous URL (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_url: Option<String>,
    /// Navigation type (link, typed, back_forward, reload)
    pub navigation_type: NavigationType,
    /// HTTP status code of navigation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Page title after navigation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Time to load page (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_time_ms: Option<u64>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Type of navigation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NavigationType {
    Link,
    Typed,
    FormSubmit,
    BackForward,
    Reload,
    Redirect,
    Script,
    Other,
}

/// Cookie change event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieChange {
    /// Cookie name
    pub name: String,
    /// Cookie value (may be redacted for security)
    pub value: String,
    /// Cookie domain
    pub domain: String,
    /// Cookie path
    pub path: String,
    /// Whether cookie is secure
    pub secure: bool,
    /// Whether cookie is HTTP-only
    pub http_only: bool,
    /// Cookie expiry (if set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    /// Whether this is a deletion
    pub deleted: bool,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Storage change event (localStorage/sessionStorage)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageChange {
    /// Storage type
    pub storage_type: StorageType,
    /// Key that changed
    pub key: String,
    /// New value (None if deleted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    /// Old value (None if new key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// URL where change occurred
    pub url: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Type of web storage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    LocalStorage,
    SessionStorage,
}

/// WebSocket message event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebSocketEvent {
    /// WebSocket URL
    pub url: String,
    /// Message direction
    pub direction: WebSocketDirection,
    /// Message data (may be truncated)
    pub data: String,
    /// Whether data was truncated
    pub truncated: bool,
    /// Whether data is binary (base64-encoded if so)
    pub is_binary: bool,
    /// Message size in bytes
    pub size: usize,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// WebSocket message direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDirection {
    Sent,
    Received,
}

/// Single session event with all possible data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEvent {
    /// Unique event ID
    pub id: String,
    /// Event type
    pub event_type: SessionEventType,
    /// Timestamp when event occurred
    pub timestamp: DateTime<Utc>,
    /// Milliseconds since recording started
    pub offset_ms: u64,
    /// Current page URL at time of event
    pub current_url: String,

    // Event-specific data (only one will be present based on event_type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub navigation: Option<NavigationEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_request: Option<NetworkRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_response: Option<NetworkResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_error: Option<NetworkError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dom_interaction: Option<DomInteraction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_message: Option<ConsoleMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<Screenshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_change: Option<CookieChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_change: Option<StorageChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_event: Option<WebSocketEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker_label: Option<String>,
}

impl SessionEvent {
    /// Create a new navigation event
    pub fn navigation(
        id: String,
        offset_ms: u64,
        current_url: String,
        navigation: NavigationEvent,
    ) -> Self {
        Self {
            id,
            event_type: SessionEventType::Navigation,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: Some(navigation),
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a new network request event
    pub fn network_request(
        id: String,
        offset_ms: u64,
        current_url: String,
        request: NetworkRequest,
    ) -> Self {
        Self {
            id,
            event_type: SessionEventType::NetworkRequest,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: Some(request),
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a new network response event
    pub fn network_response(
        id: String,
        offset_ms: u64,
        current_url: String,
        response: NetworkResponse,
    ) -> Self {
        Self {
            id,
            event_type: SessionEventType::NetworkResponse,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: None,
            network_response: Some(response),
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a new DOM interaction event
    pub fn dom_interaction(
        id: String,
        offset_ms: u64,
        current_url: String,
        interaction: DomInteraction,
    ) -> Self {
        let event_type = match interaction.interaction_type {
            DomInteractionType::Click
            | DomInteractionType::DoubleClick
            | DomInteractionType::RightClick => SessionEventType::Click,
            DomInteractionType::Input | DomInteractionType::KeyPress => SessionEventType::Input,
            DomInteractionType::Submit => SessionEventType::FormSubmit,
            DomInteractionType::Scroll => SessionEventType::Scroll,
            _ => SessionEventType::Click,
        };

        Self {
            id,
            event_type,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: Some(interaction),
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a new console message event
    pub fn console_message(
        id: String,
        offset_ms: u64,
        current_url: String,
        message: ConsoleMessage,
    ) -> Self {
        let event_type = if message.severity == ConsoleSeverity::Error {
            SessionEventType::JsError
        } else {
            SessionEventType::ConsoleMessage
        };

        Self {
            id,
            event_type,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: Some(message),
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a new screenshot event
    pub fn screenshot(
        id: String,
        offset_ms: u64,
        current_url: String,
        screenshot: Screenshot,
    ) -> Self {
        Self {
            id,
            event_type: SessionEventType::Screenshot,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: Some(screenshot),
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        }
    }

    /// Create a marker event for debugging
    pub fn marker(id: String, offset_ms: u64, current_url: String, label: String) -> Self {
        Self {
            id,
            event_type: SessionEventType::Marker,
            timestamp: Utc::now(),
            offset_ms,
            current_url,
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: Some(label),
        }
    }
}

/// Full session recording containing all events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecording {
    /// Unique recording ID
    pub id: String,
    /// Session name/description
    pub name: String,
    /// Start URL of the recording
    pub start_url: String,
    /// Recording start time
    pub started_at: DateTime<Utc>,
    /// Recording end time (None if still recording)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Total duration in milliseconds
    pub duration_ms: u64,
    /// All recorded events
    pub events: Vec<SessionEvent>,
    /// Total number of events
    pub event_count: usize,
    /// Recording metadata
    pub metadata: RecordingMetadata,
    /// Recording statistics
    pub stats: RecordingStats,
}

/// Metadata about the recording
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingMetadata {
    /// Scanner version
    pub scanner_version: String,
    /// Browser user agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Viewport width
    pub viewport_width: u32,
    /// Viewport height
    pub viewport_height: u32,
    /// Recording settings
    pub settings: RecordingSettings,
    /// Custom tags/labels
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Recording settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingSettings {
    /// Whether to capture request/response bodies
    pub capture_bodies: bool,
    /// Maximum body size to capture (bytes)
    pub max_body_size: usize,
    /// Whether to capture screenshots
    pub capture_screenshots: bool,
    /// Screenshot capture frequency (key events only, interval, etc.)
    pub screenshot_mode: ScreenshotMode,
    /// Whether to capture console messages
    pub capture_console: bool,
    /// Whether to redact sensitive data (passwords, tokens)
    pub redact_sensitive: bool,
    /// Whether to capture DOM interactions
    pub capture_dom_interactions: bool,
    /// Whether to capture storage changes
    pub capture_storage: bool,
}

impl Default for RecordingSettings {
    fn default() -> Self {
        Self {
            capture_bodies: true,
            max_body_size: 1024 * 1024, // 1MB
            capture_screenshots: true,
            screenshot_mode: ScreenshotMode::KeyEvents,
            capture_console: true,
            redact_sensitive: true,
            capture_dom_interactions: true,
            capture_storage: true,
        }
    }
}

/// Screenshot capture mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotMode {
    /// Capture only on navigation and errors
    KeyEvents,
    /// Capture at fixed intervals (ms)
    Interval(u64),
    /// Capture on every DOM interaction
    AllInteractions,
    /// Disabled
    None,
}

/// Statistics about the recording
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingStats {
    /// Total number of navigations
    pub navigations: usize,
    /// Total number of network requests
    pub network_requests: usize,
    /// Total number of network errors
    pub network_errors: usize,
    /// Total number of DOM interactions
    pub dom_interactions: usize,
    /// Total number of console messages
    pub console_messages: usize,
    /// Total number of errors/warnings
    pub errors: usize,
    /// Total number of screenshots
    pub screenshots: usize,
    /// Total data transferred (bytes)
    pub bytes_transferred: usize,
    /// Number of unique URLs visited
    pub unique_urls: usize,
}

// ============================================================================
// Session Recorder
// ============================================================================

/// State of the session recorder
#[derive(Debug, Clone, PartialEq)]
pub enum RecorderState {
    Idle,
    Recording,
    Paused,
    Stopped,
}

/// Session recorder that captures browser events during a scan
pub struct SessionRecorder {
    /// Current state
    state: Arc<RwLock<RecorderState>>,
    /// Recording settings
    settings: RecordingSettings,
    /// Start time of recording
    start_time: Arc<RwLock<Option<Instant>>>,
    /// Start URL
    start_url: Arc<RwLock<String>>,
    /// Current URL (updated during recording)
    current_url: Arc<RwLock<String>>,
    /// Recorded events
    events: Arc<Mutex<Vec<SessionEvent>>>,
    /// Event counter for ID generation
    event_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Pending network requests (for correlating with responses)
    pending_requests: Arc<Mutex<HashMap<String, Instant>>>,
    /// Statistics
    stats: Arc<Mutex<RecordingStats>>,
    /// Unique URLs seen
    unique_urls: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl SessionRecorder {
    /// Create a new session recorder with default settings
    pub fn new() -> Self {
        Self::with_settings(RecordingSettings::default())
    }

    /// Create a new session recorder with custom settings
    pub fn with_settings(settings: RecordingSettings) -> Self {
        Self {
            state: Arc::new(RwLock::new(RecorderState::Idle)),
            settings,
            start_time: Arc::new(RwLock::new(None)),
            start_url: Arc::new(RwLock::new(String::new())),
            current_url: Arc::new(RwLock::new(String::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            event_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(RecordingStats::default())),
            unique_urls: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Get the current recorder state
    pub fn state(&self) -> RecorderState {
        self.state.read().unwrap().clone()
    }

    /// Check if currently recording
    pub fn is_recording(&self) -> bool {
        matches!(*self.state.read().unwrap(), RecorderState::Recording)
    }

    /// Start recording
    pub fn start(&self, start_url: &str) {
        let mut state = self.state.write().unwrap();
        if *state != RecorderState::Idle && *state != RecorderState::Stopped {
            warn!(
                "[SessionRecorder] Cannot start recording, current state: {:?}",
                *state
            );
            return;
        }

        *state = RecorderState::Recording;
        *self.start_time.write().unwrap() = Some(Instant::now());
        *self.start_url.write().unwrap() = start_url.to_string();
        *self.current_url.write().unwrap() = start_url.to_string();
        self.events.lock().unwrap().clear();
        *self.stats.lock().unwrap() = RecordingStats::default();
        self.unique_urls.lock().unwrap().clear();
        self.unique_urls
            .lock()
            .unwrap()
            .insert(start_url.to_string());
        self.event_counter
            .store(0, std::sync::atomic::Ordering::SeqCst);

        info!("[SessionRecorder] Started recording: {}", start_url);
    }

    /// Pause recording
    pub fn pause(&self) {
        let mut state = self.state.write().unwrap();
        if *state == RecorderState::Recording {
            *state = RecorderState::Paused;
            debug!("[SessionRecorder] Recording paused");
        }
    }

    /// Resume recording
    pub fn resume(&self) {
        let mut state = self.state.write().unwrap();
        if *state == RecorderState::Paused {
            *state = RecorderState::Recording;
            debug!("[SessionRecorder] Recording resumed");
        }
    }

    /// Stop recording and return the session recording
    pub fn stop(&self) -> SessionRecording {
        let mut state = self.state.write().unwrap();
        *state = RecorderState::Stopped;

        let start_time = self.start_time.read().unwrap();
        let duration_ms = start_time
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        let events = self.events.lock().unwrap().clone();
        let stats = self.stats.lock().unwrap().clone();
        let unique_urls_count = self.unique_urls.lock().unwrap().len();

        let mut final_stats = stats;
        final_stats.unique_urls = unique_urls_count;

        let recording = SessionRecording {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!(
                "Recording {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
            ),
            start_url: self.start_url.read().unwrap().clone(),
            started_at: chrono::Utc::now() - chrono::Duration::milliseconds(duration_ms as i64),
            ended_at: Some(chrono::Utc::now()),
            duration_ms,
            event_count: events.len(),
            events,
            metadata: RecordingMetadata {
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                user_agent: None,
                viewport_width: 1920,
                viewport_height: 1080,
                settings: self.settings.clone(),
                tags: Vec::new(),
            },
            stats: final_stats,
        };

        info!(
            "[SessionRecorder] Recording stopped: {} events, {} ms",
            recording.event_count, recording.duration_ms
        );

        recording
    }

    /// Get the offset in milliseconds since recording started
    fn offset_ms(&self) -> u64 {
        self.start_time
            .read()
            .unwrap()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }

    /// Generate a unique event ID
    fn next_event_id(&self) -> String {
        let counter = self
            .event_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("evt_{}", counter)
    }

    /// Get current URL
    fn get_current_url(&self) -> String {
        self.current_url.read().unwrap().clone()
    }

    /// Update current URL
    fn set_current_url(&self, url: &str) {
        *self.current_url.write().unwrap() = url.to_string();
        self.unique_urls.lock().unwrap().insert(url.to_string());
    }

    /// Record a navigation event
    pub fn record_navigation(&self, nav: NavigationEvent) {
        if !self.is_recording() {
            return;
        }

        self.set_current_url(&nav.url);

        let event =
            SessionEvent::navigation(self.next_event_id(), self.offset_ms(), nav.url.clone(), nav);

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().navigations += 1;
        debug!("[SessionRecorder] Recorded navigation");
    }

    /// Record a network request
    pub fn record_network_request(&self, request: NetworkRequest) {
        if !self.is_recording() {
            return;
        }

        // Track pending request for response correlation
        self.pending_requests
            .lock()
            .unwrap()
            .insert(request.request_id.clone(), Instant::now());

        let current_url = self.get_current_url();
        let event = SessionEvent::network_request(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            request,
        );

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().network_requests += 1;
    }

    /// Record a network response
    pub fn record_network_response(&self, mut response: NetworkResponse) {
        if !self.is_recording() {
            return;
        }

        // Calculate duration from pending request
        if let Some(start) = self
            .pending_requests
            .lock()
            .unwrap()
            .remove(&response.request_id)
        {
            response.duration_ms = start.elapsed().as_millis() as u64;
        }

        // Update bytes transferred
        self.stats.lock().unwrap().bytes_transferred += response.size;

        let current_url = self.get_current_url();
        let event = SessionEvent::network_response(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            response,
        );

        self.events.lock().unwrap().push(event);
    }

    /// Record a network error
    pub fn record_network_error(&self, error: NetworkError) {
        if !self.is_recording() {
            return;
        }

        self.pending_requests
            .lock()
            .unwrap()
            .remove(&error.request_id);

        let current_url = self.get_current_url();
        let event = SessionEvent {
            id: self.next_event_id(),
            event_type: SessionEventType::NetworkError,
            timestamp: Utc::now(),
            offset_ms: self.offset_ms(),
            current_url,
            network_error: Some(error),
            navigation: None,
            network_request: None,
            network_response: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        };

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().network_errors += 1;
    }

    /// Record a DOM interaction
    pub fn record_dom_interaction(&self, interaction: DomInteraction) {
        if !self.is_recording() || !self.settings.capture_dom_interactions {
            return;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent::dom_interaction(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            interaction,
        );

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().dom_interactions += 1;
    }

    /// Record a console message
    pub fn record_console_message(&self, message: ConsoleMessage) {
        if !self.is_recording() || !self.settings.capture_console {
            return;
        }

        if message.severity == ConsoleSeverity::Error
            || message.severity == ConsoleSeverity::Warning
        {
            self.stats.lock().unwrap().errors += 1;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent::console_message(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            message,
        );

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().console_messages += 1;
    }

    /// Record a screenshot
    pub fn record_screenshot(&self, data: Vec<u8>, description: Option<String>) {
        if !self.is_recording() || !self.settings.capture_screenshots {
            return;
        }

        let current_url = self.get_current_url();
        let screenshot = Screenshot {
            id: uuid::Uuid::new_v4().to_string(),
            data: BASE64.encode(&data),
            format: "png".to_string(),
            width: 0, // Would be set from actual image dimensions
            height: 0,
            description,
            url: current_url.clone(),
            timestamp: Utc::now(),
        };

        let event = SessionEvent::screenshot(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            screenshot,
        );

        self.events.lock().unwrap().push(event);
        self.stats.lock().unwrap().screenshots += 1;
    }

    /// Record a cookie change
    pub fn record_cookie_change(&self, cookie: CookieChange) {
        if !self.is_recording() {
            return;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent {
            id: self.next_event_id(),
            event_type: SessionEventType::CookieChange,
            timestamp: Utc::now(),
            offset_ms: self.offset_ms(),
            current_url,
            cookie_change: Some(cookie),
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            storage_change: None,
            websocket_event: None,
            marker_label: None,
        };

        self.events.lock().unwrap().push(event);
    }

    /// Record a storage change
    pub fn record_storage_change(&self, change: StorageChange) {
        if !self.is_recording() || !self.settings.capture_storage {
            return;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent {
            id: self.next_event_id(),
            event_type: SessionEventType::StorageChange,
            timestamp: Utc::now(),
            offset_ms: self.offset_ms(),
            current_url,
            storage_change: Some(change),
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            websocket_event: None,
            marker_label: None,
        };

        self.events.lock().unwrap().push(event);
    }

    /// Record a WebSocket message
    pub fn record_websocket_message(&self, ws_event: WebSocketEvent) {
        if !self.is_recording() {
            return;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent {
            id: self.next_event_id(),
            event_type: SessionEventType::WebSocketMessage,
            timestamp: Utc::now(),
            offset_ms: self.offset_ms(),
            current_url,
            websocket_event: Some(ws_event),
            navigation: None,
            network_request: None,
            network_response: None,
            network_error: None,
            dom_interaction: None,
            console_message: None,
            screenshot: None,
            cookie_change: None,
            storage_change: None,
            marker_label: None,
        };

        self.events.lock().unwrap().push(event);
    }

    /// Add a marker event for debugging
    pub fn add_marker(&self, label: &str) {
        if !self.is_recording() {
            return;
        }

        let current_url = self.get_current_url();
        let event = SessionEvent::marker(
            self.next_event_id(),
            self.offset_ms(),
            current_url,
            label.to_string(),
        );

        self.events.lock().unwrap().push(event);
        debug!("[SessionRecorder] Marker added: {}", label);
    }

    /// Get current event count
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Get current statistics
    pub fn stats(&self) -> RecordingStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Default for SessionRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SessionRecorder {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            settings: self.settings.clone(),
            start_time: Arc::clone(&self.start_time),
            start_url: Arc::clone(&self.start_url),
            current_url: Arc::clone(&self.current_url),
            events: Arc::clone(&self.events),
            event_counter: Arc::clone(&self.event_counter),
            pending_requests: Arc::clone(&self.pending_requests),
            stats: Arc::clone(&self.stats),
            unique_urls: Arc::clone(&self.unique_urls),
        }
    }
}

// ============================================================================
// Session Exporter
// ============================================================================

/// Export format for session recordings
#[derive(Debug, Clone, PartialEq)]
pub enum ExportFormat {
    /// HAR (HTTP Archive) format - compatible with browser dev tools
    Har,
    /// JSON timeline format - custom format with all events
    Json,
    /// Compressed JSON (gzip)
    JsonCompressed,
    /// HTML report with embedded screenshots
    Html,
}

/// Session exporter for converting recordings to various formats
pub struct SessionExporter<'a> {
    recording: &'a SessionRecording,
}

impl<'a> SessionExporter<'a> {
    /// Create a new exporter for a recording
    pub fn new(recording: &'a SessionRecording) -> Self {
        Self { recording }
    }

    /// Export to the specified format
    pub fn export(&self, format: ExportFormat) -> Result<Vec<u8>> {
        match format {
            ExportFormat::Har => self.export_har(),
            ExportFormat::Json => self.export_json(),
            ExportFormat::JsonCompressed => self.export_json_compressed(),
            ExportFormat::Html => self.export_html(),
        }
    }

    /// Export to HAR (HTTP Archive) format
    pub fn export_har(&self) -> Result<Vec<u8>> {
        let har = self.build_har()?;
        let json = serde_json::to_string_pretty(&har).context("Failed to serialize HAR")?;
        Ok(json.into_bytes())
    }

    /// Build HAR structure from recording
    fn build_har(&self) -> Result<HarRoot> {
        let mut entries: Vec<HarEntry> = Vec::new();

        // Collect request/response pairs
        let mut requests: HashMap<String, &NetworkRequest> = HashMap::new();

        for event in &self.recording.events {
            if let Some(ref req) = event.network_request {
                requests.insert(req.request_id.clone(), req);
            }

            if let Some(ref resp) = event.network_response {
                if let Some(req) = requests.remove(&resp.request_id) {
                    entries.push(self.create_har_entry(req, resp));
                }
            }
        }

        Ok(HarRoot {
            log: HarLog {
                version: "1.2".to_string(),
                creator: HarCreator {
                    name: "Lonkero Security Scanner".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                browser: Some(HarBrowser {
                    name: "Chrome/Chromium (Headless)".to_string(),
                    version: "latest".to_string(),
                }),
                pages: vec![HarPage {
                    started_date_time: self.recording.started_at.to_rfc3339(),
                    id: "page_0".to_string(),
                    title: self.recording.start_url.clone(),
                    page_timings: HarPageTimings {
                        on_content_load: None,
                        on_load: Some(self.recording.duration_ms as i64),
                    },
                }],
                entries,
            },
        })
    }

    /// Create a HAR entry from request/response pair
    fn create_har_entry(&self, req: &NetworkRequest, resp: &NetworkResponse) -> HarEntry {
        HarEntry {
            started_date_time: req.timestamp.to_rfc3339(),
            time: resp.duration_ms as f64,
            request: HarRequest {
                method: req.method.to_string(),
                url: req.url.clone(),
                http_version: "HTTP/1.1".to_string(),
                cookies: Vec::new(),
                headers: req
                    .headers
                    .iter()
                    .map(|(k, v)| HarHeader {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect(),
                query_string: Vec::new(),
                post_data: req.body.as_ref().map(|body| HarPostData {
                    mime_type: req.content_type.clone().unwrap_or_default(),
                    text: Some(body.clone()),
                    params: Vec::new(),
                }),
                headers_size: -1,
                body_size: req.size as i64,
            },
            response: HarResponse {
                status: resp.status_code as i32,
                status_text: resp.status_text.clone(),
                http_version: "HTTP/1.1".to_string(),
                cookies: Vec::new(),
                headers: resp
                    .headers
                    .iter()
                    .map(|(k, v)| HarHeader {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect(),
                content: HarContent {
                    size: resp.size as i64,
                    compression: None,
                    mime_type: resp.content_type.clone().unwrap_or_default(),
                    text: resp.body.clone(),
                    encoding: None,
                },
                redirect_url: String::new(),
                headers_size: -1,
                body_size: resp.size as i64,
            },
            cache: HarCache {},
            timings: HarTimings {
                blocked: -1.0,
                dns: -1.0,
                connect: -1.0,
                send: 0.0,
                wait: resp.ttfb_ms as f64,
                receive: (resp.duration_ms - resp.ttfb_ms) as f64,
                ssl: Some(-1.0),
            },
            server_ip_address: None,
            connection: None,
            pageref: Some("page_0".to_string()),
        }
    }

    /// Export to JSON timeline format
    pub fn export_json(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_string_pretty(&self.recording)
            .context("Failed to serialize recording to JSON")?;
        Ok(json.into_bytes())
    }

    /// Export to compressed JSON (gzip)
    pub fn export_json_compressed(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_string(&self.recording)
            .context("Failed to serialize recording to JSON")?;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(json.as_bytes())
            .context("Failed to compress JSON")?;
        encoder.finish().context("Failed to finish compression")
    }

    /// Export to HTML report with embedded screenshots
    pub fn export_html(&self) -> Result<Vec<u8>> {
        let mut html = String::new();

        // HTML header
        html.push_str(&format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Recording - {}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --text-primary: #e8e8e8;
            --text-secondary: #a0a0a0;
            --accent: #e94560;
            --success: #00d4aa;
            --warning: #ffc107;
            --error: #dc3545;
            --border: #2a2a4a;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{
            background: var(--bg-secondary);
            padding: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }}
        h1 {{ color: var(--accent); font-size: 1.5rem; margin-bottom: 10px; }}
        .meta {{ display: flex; gap: 30px; flex-wrap: wrap; color: var(--text-secondary); font-size: 0.9rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat {{
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-value {{ font-size: 1.5rem; font-weight: bold; color: var(--accent); }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-secondary); }}
        .timeline {{ position: relative; padding-left: 30px; }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border);
        }}
        .event {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            position: relative;
        }}
        .event::before {{
            content: '';
            position: absolute;
            left: -24px;
            top: 20px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent);
        }}
        .event-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .event-type {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .event-type.navigation {{ background: #3498db; }}
        .event-type.network {{ background: #2ecc71; }}
        .event-type.interaction {{ background: #9b59b6; }}
        .event-type.console {{ background: #f39c12; }}
        .event-type.error {{ background: var(--error); }}
        .event-type.screenshot {{ background: #1abc9c; }}
        .event-time {{ font-size: 0.8rem; color: var(--text-secondary); }}
        .event-url {{ font-family: monospace; font-size: 0.85rem; color: var(--text-secondary); word-break: break-all; }}
        .event-details {{ font-size: 0.9rem; margin-top: 10px; }}
        .screenshot-container {{ margin-top: 10px; }}
        .screenshot-container img {{
            max-width: 100%;
            border: 1px solid var(--border);
            border-radius: 4px;
        }}
        pre {{
            background: var(--bg-tertiary);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.85rem;
        }}
        .network-status {{ font-weight: bold; }}
        .network-status.success {{ color: var(--success); }}
        .network-status.redirect {{ color: var(--warning); }}
        .network-status.error {{ color: var(--error); }}
        .filter-bar {{
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 6px 12px;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.85rem;
        }}
        .filter-btn:hover {{ background: var(--accent); }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); }}
    </style>
</head>
<body>
    <header>
        <h1>Session Recording Report</h1>
        <div class="meta">
            <span><strong>URL:</strong> {}</span>
            <span><strong>Duration:</strong> {}ms</span>
            <span><strong>Events:</strong> {}</span>
            <span><strong>Started:</strong> {}</span>
        </div>
    </header>
    <div class="container">
"#,
            self.recording.id,
            self.recording.start_url,
            self.recording.duration_ms,
            self.recording.event_count,
            self.recording.started_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Statistics
        html.push_str(&format!(
            r#"
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Navigations</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Network Requests</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">DOM Interactions</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Console Messages</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Errors</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Screenshots</div>
            </div>
        </div>
"#,
            self.recording.stats.navigations,
            self.recording.stats.network_requests,
            self.recording.stats.dom_interactions,
            self.recording.stats.console_messages,
            self.recording.stats.errors,
            self.recording.stats.screenshots,
        ));

        // Filter bar
        html.push_str(
            r#"
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterEvents('all')">All</button>
            <button class="filter-btn" onclick="filterEvents('navigation')">Navigation</button>
            <button class="filter-btn" onclick="filterEvents('network')">Network</button>
            <button class="filter-btn" onclick="filterEvents('interaction')">Interactions</button>
            <button class="filter-btn" onclick="filterEvents('console')">Console</button>
            <button class="filter-btn" onclick="filterEvents('error')">Errors</button>
            <button class="filter-btn" onclick="filterEvents('screenshot')">Screenshots</button>
        </div>
        <div class="timeline">
"#,
        );

        // Events
        for event in &self.recording.events {
            html.push_str(&self.render_event_html(event));
        }

        // Footer and scripts
        html.push_str(
            r#"
        </div>
    </div>
    <script>
        function filterEvents(type) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('.event').forEach(el => {
                if (type === 'all' || el.dataset.type === type) {
                    el.style.display = 'block';
                } else {
                    el.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"#,
        );

        Ok(html.into_bytes())
    }

    /// Render a single event as HTML
    fn render_event_html(&self, event: &SessionEvent) -> String {
        let (event_type_class, event_type_label, details) = match event.event_type {
            SessionEventType::Navigation => {
                let nav = event.navigation.as_ref().unwrap();
                (
                    "navigation",
                    "Navigation",
                    format!(
                        "<div class='event-url'>{}</div>",
                        html_escape::encode_text(&nav.url)
                    ),
                )
            }
            SessionEventType::NetworkRequest => {
                let req = event.network_request.as_ref().unwrap();
                (
                    "network",
                    "Request",
                    format!(
                        "<div><strong>{}</strong> <span class='event-url'>{}</span></div>",
                        req.method,
                        html_escape::encode_text(&req.url)
                    ),
                )
            }
            SessionEventType::NetworkResponse => {
                let resp = event.network_response.as_ref().unwrap();
                let status_class = if resp.status_code < 300 {
                    "success"
                } else if resp.status_code < 400 {
                    "redirect"
                } else {
                    "error"
                };
                (
                    "network",
                    "Response",
                    format!(
                        "<div><span class='network-status {}'>{} {}</span> - {} bytes in {}ms</div>",
                        status_class, resp.status_code, resp.status_text, resp.size, resp.duration_ms
                    ),
                )
            }
            SessionEventType::NetworkError => {
                let err = event.network_error.as_ref().unwrap();
                (
                    "error",
                    "Network Error",
                    format!("<div>{}</div>", html_escape::encode_text(&err.message)),
                )
            }
            SessionEventType::Click
            | SessionEventType::Input
            | SessionEventType::FormSubmit
            | SessionEventType::Scroll => {
                let dom = event.dom_interaction.as_ref().unwrap();
                (
                    "interaction",
                    match event.event_type {
                        SessionEventType::Click => "Click",
                        SessionEventType::Input => "Input",
                        SessionEventType::FormSubmit => "Form Submit",
                        SessionEventType::Scroll => "Scroll",
                        _ => "Interaction",
                    },
                    format!(
                        "<div>&lt;{}&gt; {}</div>",
                        html_escape::encode_text(&dom.tag_name),
                        html_escape::encode_text(&dom.selector)
                    ),
                )
            }
            SessionEventType::ConsoleMessage => {
                let msg = event.console_message.as_ref().unwrap();
                (
                    "console",
                    match msg.severity {
                        ConsoleSeverity::Error => "Console Error",
                        ConsoleSeverity::Warning => "Console Warning",
                        _ => "Console",
                    },
                    format!("<pre>{}</pre>", html_escape::encode_text(&msg.text)),
                )
            }
            SessionEventType::JsError => {
                let msg = event.console_message.as_ref().unwrap();
                (
                    "error",
                    "JS Error",
                    format!("<pre>{}</pre>", html_escape::encode_text(&msg.text)),
                )
            }
            SessionEventType::Screenshot => {
                let ss = event.screenshot.as_ref().unwrap();
                (
                    "screenshot",
                    "Screenshot",
                    format!(
                        "<div class='screenshot-container'><img src='data:image/png;base64,{}' alt='Screenshot'/></div>",
                        ss.data
                    ),
                )
            }
            SessionEventType::CookieChange => ("network", "Cookie", String::new()),
            SessionEventType::StorageChange => ("network", "Storage", String::new()),
            SessionEventType::WebSocketMessage => ("network", "WebSocket", String::new()),
            SessionEventType::Marker => {
                let label = event.marker_label.as_ref().unwrap();
                (
                    "navigation",
                    "Marker",
                    format!("<div>{}</div>", html_escape::encode_text(label)),
                )
            }
        };

        format!(
            r#"
            <div class="event" data-type="{}">
                <div class="event-header">
                    <span class="event-type {}">{}</span>
                    <span class="event-time">+{}ms</span>
                </div>
                <div class="event-details">{}</div>
            </div>
"#,
            event_type_class, event_type_class, event_type_label, event.offset_ms, details
        )
    }
}

// ============================================================================
// HAR Format Types (HTTP Archive 1.2)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct HarRoot {
    pub log: HarLog,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<HarBrowser>,
    pub pages: Vec<HarPage>,
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarBrowser {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarPage {
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    pub page_timings: HarPageTimings,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarPageTimings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_content_load: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_load: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarEntry {
    pub started_date_time: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    pub cache: HarCache,
    pub timings: HarTimings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pageref: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    pub query_string: Vec<HarQueryParam>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarResponse {
    pub status: i32,
    pub status_text: String,
    pub http_version: String,
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarCookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarPostData {
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub params: Vec<HarParam>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarParam {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarContent {
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarCache {}

#[derive(Debug, Serialize, Deserialize)]
pub struct HarTimings {
    pub blocked: f64,
    pub dns: f64,
    pub connect: f64,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl: Option<f64>,
}

// ============================================================================
// Compression Utilities
// ============================================================================

/// Compression utilities for session recordings
pub struct RecordingCompression;

impl RecordingCompression {
    /// Compress a recording to gzip format
    pub fn compress(recording: &SessionRecording) -> Result<Vec<u8>> {
        let json = serde_json::to_string(recording).context("Failed to serialize recording")?;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(json.as_bytes())
            .context("Failed to compress")?;
        encoder.finish().context("Failed to finish compression")
    }

    /// Decompress a gzip-compressed recording
    pub fn decompress(data: &[u8]) -> Result<SessionRecording> {
        let mut decoder = GzDecoder::new(data);
        let mut json = String::new();
        decoder
            .read_to_string(&mut json)
            .context("Failed to decompress")?;

        serde_json::from_str(&json).context("Failed to parse recording")
    }

    /// Calculate compression ratio
    pub fn compression_ratio(original: &SessionRecording, compressed: &[u8]) -> f64 {
        let original_size = serde_json::to_string(original)
            .map(|s| s.len())
            .unwrap_or(0);

        if original_size == 0 {
            return 0.0;
        }

        1.0 - (compressed.len() as f64 / original_size as f64)
    }
}

// ============================================================================
// Vulnerability Attachment
// ============================================================================

/// Attachment information for linking recordings to vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingAttachment {
    /// Recording ID
    pub recording_id: String,
    /// Start offset in recording (ms) - where the relevant action begins
    pub start_offset_ms: u64,
    /// End offset in recording (ms) - where the relevant action ends
    pub end_offset_ms: u64,
    /// Specific event IDs that are relevant to this vulnerability
    pub relevant_event_ids: Vec<String>,
    /// Description of what the recording shows
    pub description: String,
}

impl SessionRecording {
    /// Create an attachment reference for a vulnerability report
    pub fn create_attachment(
        &self,
        start_offset_ms: u64,
        end_offset_ms: u64,
        description: &str,
    ) -> RecordingAttachment {
        // Find events within the time range
        let relevant_event_ids: Vec<String> = self
            .events
            .iter()
            .filter(|e| e.offset_ms >= start_offset_ms && e.offset_ms <= end_offset_ms)
            .map(|e| e.id.clone())
            .collect();

        RecordingAttachment {
            recording_id: self.id.clone(),
            start_offset_ms,
            end_offset_ms,
            relevant_event_ids,
            description: description.to_string(),
        }
    }

    /// Extract a sub-recording containing only events within a time range
    pub fn extract_segment(&self, start_offset_ms: u64, end_offset_ms: u64) -> SessionRecording {
        let events: Vec<SessionEvent> = self
            .events
            .iter()
            .filter(|e| e.offset_ms >= start_offset_ms && e.offset_ms <= end_offset_ms)
            .cloned()
            .collect();

        let mut stats = RecordingStats::default();
        for event in &events {
            match event.event_type {
                SessionEventType::Navigation => stats.navigations += 1,
                SessionEventType::NetworkRequest => stats.network_requests += 1,
                SessionEventType::NetworkError => stats.network_errors += 1,
                SessionEventType::Click
                | SessionEventType::Input
                | SessionEventType::FormSubmit
                | SessionEventType::Scroll => stats.dom_interactions += 1,
                SessionEventType::ConsoleMessage | SessionEventType::JsError => {
                    stats.console_messages += 1;
                    if event.event_type == SessionEventType::JsError {
                        stats.errors += 1;
                    }
                }
                SessionEventType::Screenshot => stats.screenshots += 1,
                _ => {}
            }
        }

        SessionRecording {
            id: format!("{}-segment", self.id),
            name: format!(
                "{} ({}ms - {}ms)",
                self.name, start_offset_ms, end_offset_ms
            ),
            start_url: self.start_url.clone(),
            started_at: self.started_at + chrono::Duration::milliseconds(start_offset_ms as i64),
            ended_at: Some(self.started_at + chrono::Duration::milliseconds(end_offset_ms as i64)),
            duration_ms: end_offset_ms - start_offset_ms,
            event_count: events.len(),
            events,
            metadata: self.metadata.clone(),
            stats,
        }
    }
}

// Note: flate2 crate is used for compression (added to Cargo.toml)

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_recorder_lifecycle() {
        let recorder = SessionRecorder::new();
        assert_eq!(recorder.state(), RecorderState::Idle);

        recorder.start("https://example.com");
        assert_eq!(recorder.state(), RecorderState::Recording);
        assert!(recorder.is_recording());

        recorder.pause();
        assert_eq!(recorder.state(), RecorderState::Paused);
        assert!(!recorder.is_recording());

        recorder.resume();
        assert_eq!(recorder.state(), RecorderState::Recording);

        let recording = recorder.stop();
        assert_eq!(recorder.state(), RecorderState::Stopped);
        assert_eq!(recording.start_url, "https://example.com");
    }

    #[test]
    fn test_record_navigation() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        recorder.record_navigation(NavigationEvent {
            url: "https://example.com/page".to_string(),
            from_url: Some("https://example.com".to_string()),
            navigation_type: NavigationType::Link,
            status_code: Some(200),
            title: Some("Test Page".to_string()),
            load_time_ms: Some(150),
            timestamp: Utc::now(),
        });

        let recording = recorder.stop();
        assert_eq!(recording.stats.navigations, 1);
        assert_eq!(recording.events.len(), 1);
        assert_eq!(recording.events[0].event_type, SessionEventType::Navigation);
    }

    #[test]
    fn test_record_network_request_response() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        let request_id = "req_123".to_string();

        recorder.record_network_request(NetworkRequest {
            request_id: request_id.clone(),
            url: "https://api.example.com/data".to_string(),
            method: HttpMethod::Get,
            headers: HashMap::new(),
            body: None,
            content_type: None,
            size: 0,
            timestamp: Utc::now(),
            initiator: Some("fetch".to_string()),
            stack_trace: None,
        });

        std::thread::sleep(std::time::Duration::from_millis(10));

        recorder.record_network_response(NetworkResponse {
            request_id: request_id.clone(),
            status_code: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: Some("{\"data\": \"test\"}".to_string()),
            body_truncated: false,
            content_type: Some("application/json".to_string()),
            size: 16,
            ttfb_ms: 5,
            duration_ms: 0, // Will be calculated
            timestamp: Utc::now(),
            from_cache: false,
        });

        let recording = recorder.stop();
        assert_eq!(recording.stats.network_requests, 1);
        assert_eq!(recording.events.len(), 2);
    }

    #[test]
    fn test_record_dom_interaction() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        recorder.record_dom_interaction(DomInteraction {
            interaction_type: DomInteractionType::Click,
            selector: "button#submit".to_string(),
            xpath: Some("/html/body/form/button".to_string()),
            tag_name: "BUTTON".to_string(),
            element_id: Some("submit".to_string()),
            classes: vec!["btn".to_string(), "btn-primary".to_string()],
            text_content: Some("Submit".to_string()),
            input_value: None,
            scroll_position: None,
            coordinates: Some(ClickCoordinates {
                x: 100,
                y: 200,
                viewport_x: 100,
                viewport_y: 200,
            }),
            timestamp: Utc::now(),
        });

        let recording = recorder.stop();
        assert_eq!(recording.stats.dom_interactions, 1);
        assert_eq!(recording.events[0].event_type, SessionEventType::Click);
    }

    #[test]
    fn test_record_console_message() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        recorder.record_console_message(ConsoleMessage {
            severity: ConsoleSeverity::Error,
            text: "Uncaught TypeError: Cannot read property 'foo' of undefined".to_string(),
            source_url: Some("https://example.com/app.js".to_string()),
            line_number: Some(42),
            column_number: Some(10),
            stack_trace: None,
            timestamp: Utc::now(),
        });

        let recording = recorder.stop();
        assert_eq!(recording.stats.console_messages, 1);
        assert_eq!(recording.stats.errors, 1);
        assert_eq!(recording.events[0].event_type, SessionEventType::JsError);
    }

    #[test]
    fn test_add_marker() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        recorder.add_marker("vulnerability_detected");

        let recording = recorder.stop();
        assert_eq!(recording.events.len(), 1);
        assert_eq!(recording.events[0].event_type, SessionEventType::Marker);
        assert_eq!(
            recording.events[0].marker_label.as_ref().unwrap(),
            "vulnerability_detected"
        );
    }

    #[test]
    fn test_export_json() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");
        recorder.add_marker("test");
        let recording = recorder.stop();

        let exporter = SessionExporter::new(&recording);
        let json = exporter.export(ExportFormat::Json).unwrap();

        assert!(!json.is_empty());
        let parsed: SessionRecording = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.start_url, "https://example.com");
    }

    #[test]
    fn test_export_har() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        recorder.record_network_request(NetworkRequest {
            request_id: "req_1".to_string(),
            url: "https://example.com/api".to_string(),
            method: HttpMethod::Get,
            headers: HashMap::new(),
            body: None,
            content_type: None,
            size: 0,
            timestamp: Utc::now(),
            initiator: None,
            stack_trace: None,
        });

        recorder.record_network_response(NetworkResponse {
            request_id: "req_1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: Some("{}".to_string()),
            body_truncated: false,
            content_type: Some("application/json".to_string()),
            size: 2,
            ttfb_ms: 10,
            duration_ms: 50,
            timestamp: Utc::now(),
            from_cache: false,
        });

        let recording = recorder.stop();

        let exporter = SessionExporter::new(&recording);
        let har = exporter.export(ExportFormat::Har).unwrap();

        assert!(!har.is_empty());
        let parsed: HarRoot = serde_json::from_slice(&har).unwrap();
        assert_eq!(parsed.log.version, "1.2");
        assert_eq!(parsed.log.entries.len(), 1);
    }

    #[test]
    fn test_export_html() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");
        recorder.add_marker("test");
        let recording = recorder.stop();

        let exporter = SessionExporter::new(&recording);
        let html = exporter.export(ExportFormat::Html).unwrap();

        let html_str = String::from_utf8(html).unwrap();
        assert!(html_str.contains("<!DOCTYPE html>"));
        assert!(html_str.contains("Session Recording Report"));
        assert!(html_str.contains("https://example.com"));
    }

    #[test]
    fn test_extract_segment() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");

        // Add events at different times
        recorder.add_marker("start");
        std::thread::sleep(std::time::Duration::from_millis(50));
        recorder.add_marker("middle");
        std::thread::sleep(std::time::Duration::from_millis(50));
        recorder.add_marker("end");

        let recording = recorder.stop();

        // Extract middle segment
        let segment = recording.extract_segment(25, 75);
        assert!(segment.events.len() >= 1);
    }

    #[test]
    fn test_create_attachment() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");
        recorder.add_marker("vuln_trigger");
        let recording = recorder.stop();

        let attachment = recording.create_attachment(0, 1000, "XSS vulnerability triggered");

        assert_eq!(attachment.recording_id, recording.id);
        assert!(!attachment.relevant_event_ids.is_empty());
        assert_eq!(attachment.description, "XSS vulnerability triggered");
    }

    #[test]
    fn test_http_method_from_string() {
        assert_eq!(HttpMethod::from("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from("DELETE"), HttpMethod::Delete);
        assert_eq!(HttpMethod::from("unknown"), HttpMethod::Get);
    }

    #[test]
    fn test_recording_settings_default() {
        let settings = RecordingSettings::default();
        assert!(settings.capture_bodies);
        assert!(settings.capture_screenshots);
        assert!(settings.capture_console);
        assert!(settings.redact_sensitive);
        assert_eq!(settings.max_body_size, 1024 * 1024);
    }

    #[test]
    fn test_recorder_clone() {
        let recorder = SessionRecorder::new();
        recorder.start("https://example.com");
        recorder.add_marker("test");

        let cloned = recorder.clone();
        assert!(cloned.is_recording());
        assert_eq!(cloned.event_count(), 1);
    }
}
