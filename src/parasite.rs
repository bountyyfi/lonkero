//! Parasite Mode - Route requests through real browser TLS
//!
//! This module enables "Parasite Mode" where Lonkero routes HTTP requests
//! through a Chrome extension running in the user's real browser. This means:
//!
//! - **Real JA3/JA4 fingerprints** - TLS handshake done by actual Chrome
//! - **Real HTTP/2 settings** - Authentic browser behavior
//! - **Undetectable** - WAFs/CDNs see genuine browser traffic
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     WebSocket      ┌──────────────────┐
//! │  Lonkero Rust   │◄──────────────────►│ Chrome Extension │
//! │  (WS Server)    │   localhost:9339   │ (real browser)   │
//! └─────────────────┘                    └────────┬─────────┘
//!                                                 │
//!                                           fetch() with
//!                                           REAL TLS fingerprint
//!                                                 │
//!                                                 ▼
//!                                        ┌────────────────┐
//!                                        │ Target Website │
//!                                        └────────────────┘
//! ```

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_tungstenite::{accept_async_with_config, tungstenite::protocol::WebSocketConfig, tungstenite::Message};
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Default WebSocket port for Parasite Mode
pub const DEFAULT_PARASITE_PORT: u16 = 9340;

/// Request to be proxied through the browser
#[derive(Debug, Clone, Serialize)]
pub struct ParasiteRequest {
    pub id: u64,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub url: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub timeout: u64,
}

/// Response from the browser extension
#[derive(Debug, Clone, Deserialize)]
pub struct ParasiteResponse {
    pub id: u64,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub status_text: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub duration: u64,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Handshake message from extension
#[derive(Debug, Deserialize)]
struct HandshakeMessage {
    #[serde(rename = "type")]
    msg_type: String,
    version: String,
    #[serde(rename = "userAgent")]
    user_agent: String,
    platform: String,
    #[serde(default)]
    challenge: Option<String>,
}

/// Handshake acknowledgment sent back to extension
#[derive(Debug, Serialize)]
struct HandshakeAck {
    #[serde(rename = "type")]
    msg_type: String,
    challenge: String,
    #[serde(rename = "challengeResponse", skip_serializing_if = "Option::is_none")]
    challenge_response: Option<String>,
    #[serde(rename = "licenseKey", skip_serializing_if = "Option::is_none")]
    license_key: Option<String>,
}

/// Generic incoming message
#[derive(Debug, Deserialize)]
struct IncomingMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    id: u64,
}

/// Parasite Mode client state
pub struct ParasiteClient {
    is_connected: Arc<AtomicBool>,
    request_counter: AtomicU64,
    request_tx: mpsc::Sender<ParasiteRequest>,
    pending_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<ParasiteResponse>>>>,
    browser_info: Arc<RwLock<Option<BrowserInfo>>>,
    stats: Arc<ParasiteStats>,
    license_key: Option<String>,
}

/// Connected browser information
#[derive(Debug, Clone)]
pub struct BrowserInfo {
    pub user_agent: String,
    pub platform: String,
    pub extension_version: String,
}

/// Statistics for Parasite Mode
#[derive(Debug, Default)]
pub struct ParasiteStats {
    pub requests_sent: AtomicU64,
    pub requests_completed: AtomicU64,
    pub requests_failed: AtomicU64,
    pub total_bytes: AtomicU64,
}

impl ParasiteClient {
    /// Create new Parasite client and start WebSocket server
    pub async fn new(port: u16, license_key: Option<String>) -> Result<Arc<Self>> {
        let (request_tx, request_rx) = mpsc::channel::<ParasiteRequest>(1000);
        let pending_requests = Arc::new(RwLock::new(HashMap::new()));
        let is_connected = Arc::new(AtomicBool::new(false));
        let browser_info = Arc::new(RwLock::new(None));
        let stats = Arc::new(ParasiteStats::default());

        let client = Arc::new(Self {
            is_connected: is_connected.clone(),
            request_counter: AtomicU64::new(1),
            request_tx,
            pending_requests: pending_requests.clone(),
            browser_info: browser_info.clone(),
            stats: stats.clone(),
            license_key: license_key.clone(),
        });

        // Start WebSocket server in background
        let pending_clone = pending_requests.clone();
        let connected_clone = is_connected.clone();
        let browser_clone = browser_info.clone();
        let stats_clone = stats.clone();

        tokio::spawn(async move {
            if let Err(e) = run_server(
                port,
                request_rx,
                pending_clone,
                connected_clone,
                browser_clone,
                stats_clone,
                license_key,
            )
            .await
            {
                error!("Parasite server error: {}", e);
            }
        });

        info!("Parasite Mode WebSocket server starting on port {}", port);
        Ok(client)
    }

    /// Check if browser extension is connected
    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::SeqCst)
    }

    /// Get connected browser info
    pub async fn browser_info(&self) -> Option<BrowserInfo> {
        self.browser_info.read().await.clone()
    }

    /// Get statistics
    pub fn stats(&self) -> &ParasiteStats {
        &self.stats
    }

    /// Make HTTP request through browser's TLS stack
    pub async fn request(
        &self,
        url: &str,
        method: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        timeout_ms: u64,
    ) -> Result<ParasiteResponse> {
        if !self.is_connected() {
            return Err(anyhow!(
                "Parasite Mode: No browser connected. Install the extension and open Chrome."
            ));
        }

        let id = self.request_counter.fetch_add(1, Ordering::SeqCst);

        let request = ParasiteRequest {
            id,
            msg_type: "request".to_string(),
            url: url.to_string(),
            method: method.to_string(),
            headers,
            body,
            timeout: timeout_ms,
        };

        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(id, response_tx);
        }

        // Send request to extension
        self.request_tx
            .send(request)
            .await
            .map_err(|_| anyhow!("Failed to send request to browser"))?;

        self.stats.requests_sent.fetch_add(1, Ordering::SeqCst);

        // Wait for response with timeout
        let timeout_duration = Duration::from_millis(timeout_ms + 5000); // Extra buffer
        match tokio::time::timeout(timeout_duration, response_rx).await {
            Ok(Ok(response)) => {
                if response.error.is_some() {
                    self.stats.requests_failed.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.stats.requests_completed.fetch_add(1, Ordering::SeqCst);
                    self.stats
                        .total_bytes
                        .fetch_add(response.body.len() as u64, Ordering::SeqCst);
                }
                Ok(response)
            }
            Ok(Err(_)) => {
                self.stats.requests_failed.fetch_add(1, Ordering::SeqCst);
                Err(anyhow!("Browser extension dropped request"))
            }
            Err(_) => {
                // Remove from pending
                let mut pending = self.pending_requests.write().await;
                pending.remove(&id);
                self.stats.requests_failed.fetch_add(1, Ordering::SeqCst);
                Err(anyhow!("Request timed out waiting for browser"))
            }
        }
    }

    /// Convenience method for GET request
    pub async fn get(&self, url: &str) -> Result<ParasiteResponse> {
        self.request(url, "GET", None, None, 30000).await
    }

    /// Convenience method for POST request
    pub async fn post(&self, url: &str, body: &str, content_type: &str) -> Result<ParasiteResponse> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), content_type.to_string());
        self.request(url, "POST", Some(headers), Some(body.to_string()), 30000)
            .await
    }
}

/// Run the WebSocket server
async fn run_server(
    port: u16,
    mut request_rx: mpsc::Receiver<ParasiteRequest>,
    pending_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<ParasiteResponse>>>>,
    is_connected: Arc<AtomicBool>,
    browser_info: Arc<RwLock<Option<BrowserInfo>>>,
    stats: Arc<ParasiteStats>,
    license_key: Option<String>,
) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);

    // Create socket with SO_REUSEADDR to allow rebinding after unclean shutdown
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    let addr_parsed: std::net::SocketAddr = addr.parse()?;
    socket.bind(&addr_parsed.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)?;

    info!("Parasite Mode listening on ws://{}/parasite", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("Browser extension connecting from {}", peer_addr);

                let pending = pending_requests.clone();
                let connected = is_connected.clone();
                let browser = browser_info.clone();
                let stats = stats.clone();

                // Take ownership of request receiver for this connection
                let request_rx_opt = Some(&mut request_rx);

                if let Err(e) = handle_connection(
                    stream,
                    request_rx_opt.unwrap(),
                    pending,
                    connected,
                    browser,
                    stats,
                    license_key.clone(),
                )
                .await
                {
                    warn!("Connection error: {}", e);
                }

                is_connected.store(false, Ordering::SeqCst);
                *browser_info.write().await = None;
                info!("Browser extension disconnected");
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a single WebSocket connection
async fn handle_connection(
    stream: TcpStream,
    request_rx: &mut mpsc::Receiver<ParasiteRequest>,
    pending_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<ParasiteResponse>>>>,
    is_connected: Arc<AtomicBool>,
    browser_info: Arc<RwLock<Option<BrowserInfo>>>,
    _stats: Arc<ParasiteStats>,
    license_key: Option<String>,
) -> Result<()> {
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(4 * 1024 * 1024);  // 4 MB max (was 64 MB default)
    ws_config.max_frame_size = Some(2 * 1024 * 1024);    // 2 MB max frame
    let ws_stream = accept_async_with_config(stream, Some(ws_config)).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Wait for handshake
    let handshake_timeout = Duration::from_secs(10);
    let handshake_msg = tokio::time::timeout(handshake_timeout, ws_receiver.next())
        .await
        .map_err(|_| anyhow!("Handshake timeout"))?
        .ok_or_else(|| anyhow!("Connection closed before handshake"))?
        .map_err(|e| anyhow!("WebSocket error: {}", e))?;

    if let Message::Text(text) = handshake_msg {
        let handshake: HandshakeMessage =
            serde_json::from_str(&text).map_err(|e| anyhow!("Invalid handshake: {}", e))?;

        if handshake.msg_type != "handshake" {
            return Err(anyhow!("Expected handshake, got: {}", handshake.msg_type));
        }

        info!(
            "Browser connected: {} on {} (ext v{})",
            handshake.user_agent, handshake.platform, handshake.version
        );

        *browser_info.write().await = Some(BrowserInfo {
            user_agent: handshake.user_agent,
            platform: handshake.platform,
            extension_version: handshake.version,
        });

        // Send handshakeAck with HMAC challenge-response + challenge echo
        // HMAC uses license key as shared secret so only the real CLI can authenticate
        if let Some(ref challenge) = handshake.challenge {
            let challenge_response = license_key.as_ref().map(|key| {
                let mut mac = HmacSha256::new_from_slice(key.as_bytes())
                    .expect("HMAC key length");
                mac.update(challenge.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            });

            let ack = HandshakeAck {
                msg_type: "handshakeAck".to_string(),
                challenge: challenge.clone(),
                challenge_response,
                license_key: license_key.clone(),
            };
            let ack_json = serde_json::to_string(&ack)?;
            ws_sender.send(Message::Text(ack_json.into())).await?;
            info!("Sent handshakeAck to authenticate with extension");
        }

        is_connected.store(true, Ordering::SeqCst);
    } else {
        return Err(anyhow!("Expected text message for handshake"));
    }

    // Main message loop
    loop {
        tokio::select! {
            // Receive response from browser
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Parse message type first
                        if let Ok(incoming) = serde_json::from_str::<IncomingMessage>(&text) {
                            match incoming.msg_type.as_str() {
                                "response" | "error" => {
                                    if let Ok(response) = serde_json::from_str::<ParasiteResponse>(&text) {
                                        let mut pending = pending_requests.write().await;
                                        if let Some(tx) = pending.remove(&response.id) {
                                            let _ = tx.send(response);
                                        }
                                    }
                                }
                                "pong" | "heartbeat" => {
                                    debug!("Received {} from browser", incoming.msg_type);
                                }
                                _ => {
                                    debug!("Unknown message type: {}", incoming.msg_type);
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("Browser sent close frame");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        info!("WebSocket stream ended");
                        break;
                    }
                    _ => {}
                }
            }

            // Send request to browser
            request = request_rx.recv() => {
                if let Some(req) = request {
                    let json = serde_json::to_string(&req)?;
                    if let Err(e) = ws_sender.send(Message::Text(json.into())).await {
                        warn!("Failed to send request to browser: {}", e);
                        // Put request back? Or fail it?
                        let mut pending = pending_requests.write().await;
                        if let Some(tx) = pending.remove(&req.id) {
                            let _ = tx.send(ParasiteResponse {
                                id: req.id,
                                msg_type: "error".to_string(),
                                status: 0,
                                status_text: String::new(),
                                headers: HashMap::new(),
                                body: String::new(),
                                url: req.url,
                                duration: 0,
                                error: Some("send_failed".to_string()),
                                message: Some(e.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Convert ParasiteResponse to HttpResponse for seamless integration
impl From<ParasiteResponse> for crate::http_client::HttpResponse {
    fn from(resp: ParasiteResponse) -> Self {
        Self {
            status_code: resp.status,
            body: resp.body,
            headers: resp.headers,
            duration_ms: resp.duration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = ParasiteRequest {
            id: 1,
            msg_type: "request".to_string(),
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            headers: None,
            body: None,
            timeout: 30000,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"type\":\"request\""));
        assert!(!json.contains("\"headers\":")); // skip_serializing_if
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{
            "type": "response",
            "id": 1,
            "status": 200,
            "statusText": "OK",
            "headers": {"content-type": "text/html"},
            "body": "<html></html>",
            "url": "https://example.com",
            "duration": 150
        }"#;

        let resp: ParasiteResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 1);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.duration, 150);
    }
}
