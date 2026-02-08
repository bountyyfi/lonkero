// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - WebSocket Security Scanner
 * Tests for WebSocket vulnerabilities and misconfigurations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info};

pub struct WebSocketScanner {
    http_client: Arc<HttpClient>,
}

impl WebSocketScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for WebSocket vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[WebSocket] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Detect WebSocket endpoints (passive detection from response)
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                info!("[NOTE] [WebSocket] Could not fetch URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Intelligent detection
        let characteristics = AppCharacteristics::from_response(&response, url);
        let is_websocket = self.detect_websocket_endpoint(&response, url);

        // Test 2: Active WebSocket endpoint discovery (probe common paths)
        tests_run += 1;
        let discovered_endpoints = self.discover_websocket_endpoints(url).await;

        // If not detected passively and no active discovery, skip WebSocket tests
        if !is_websocket && discovered_endpoints.is_empty() {
            debug!("[NOTE] [WebSocket] Not a WebSocket endpoint");
            return Ok((vulnerabilities, tests_run));
        }

        // Store characteristics for later use in tests
        let _app_chars = characteristics;

        info!("[SUCCESS] [WebSocket] WebSocket endpoint detected");

        // Report discovered endpoints
        if !discovered_endpoints.is_empty() {
            info!(
                "[WebSocket] Discovered {} WebSocket endpoints: {:?}",
                discovered_endpoints.len(),
                discovered_endpoints
            );
        }

        // Test 3: Check for missing origin validation
        tests_run += 1;
        self.check_origin_validation(&response, url, &mut vulnerabilities);

        // Test 4: Check for missing authentication
        tests_run += 1;
        self.check_authentication(&response, url, &mut vulnerabilities);

        // Test 5: Test CSWSH (Cross-Site WebSocket Hijacking)
        tests_run += 1;
        if let Ok(cswsh_response) = self.test_cswsh(url).await {
            self.check_cswsh(&cswsh_response, url, &mut vulnerabilities);
        }

        // Test 6: Check for sensitive data in WebSocket URL
        tests_run += 1;
        self.check_sensitive_data_in_url(url, &mut vulnerabilities);

        // Test 7: Check for tunnel/message injection
        tests_run += 1;
        self.check_message_injection(&response, url, &mut vulnerabilities);

        // Test 8: Check for rate limiting
        tests_run += 1;
        self.check_rate_limiting(&response, url, &mut vulnerabilities);

        // Test 9: Check WebSocket Sec headers
        tests_run += 1;
        self.check_sec_headers(&response, url, &mut vulnerabilities);

        // Try to convert HTTP(S) URL to WebSocket URL for exploitation tests
        let ws_url = self.convert_to_ws_url(url);
        if let Some(ws_url) = &ws_url {
            // Test 10: WebSocket CSRF
            tests_run += 1;
            if let Ok(csrf_vulns) = self.test_websocket_csrf(ws_url).await {
                vulnerabilities.extend(csrf_vulns);
            }

            // Test 11: WebSocket Message Injection
            tests_run += 1;
            if let Ok(injection_vulns) = self.test_message_injection(ws_url).await {
                vulnerabilities.extend(injection_vulns);
            }

            // Test 12: WebSocket Origin Bypass (exploitation)
            tests_run += 1;
            if let Ok(origin_vulns) = self.test_origin_bypass(ws_url).await {
                vulnerabilities.extend(origin_vulns);
            }

            // Test 13: WebSocket Hijacking
            tests_run += 1;
            if let Ok(hijack_vulns) = self.test_websocket_hijacking(ws_url).await {
                vulnerabilities.extend(hijack_vulns);
            }

            // Test 14: WebSocket Denial of Service (limited)
            tests_run += 1;
            if let Ok(dos_vulns) = self.test_websocket_dos(ws_url).await {
                vulnerabilities.extend(dos_vulns);
            }

            // Test 15: WebSocket Protocol Confusion
            tests_run += 1;
            if let Ok(confusion_vulns) = self.test_protocol_confusion(ws_url).await {
                vulnerabilities.extend(confusion_vulns);
            }
        }

        // Test discovered endpoints as well
        for endpoint in discovered_endpoints {
            // Test 16+: Test each discovered endpoint for CSWSH
            tests_run += 1;
            if let Ok(origin_vulns) = self.test_origin_bypass(&endpoint).await {
                vulnerabilities.extend(origin_vulns);
            }
        }

        info!(
            "[SUCCESS] [WebSocket] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect WebSocket endpoint
    fn detect_websocket_endpoint(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
    ) -> bool {
        let body_lower = response.body.to_lowercase();

        // Check URL for ws:// or wss://
        let url_lower = url.to_lowercase();
        if url_lower.contains("ws://") || url_lower.contains("wss://") {
            return true;
        }

        // Check response body for WebSocket indicators
        body_lower.contains("websocket")
            || body_lower.contains("ws://")
            || body_lower.contains("wss://")
            || body_lower.contains("socket.io")
            || body_lower.contains("sockjs")
            || response
                .header("upgrade")
                .map_or(false, |h| h.to_lowercase() == "websocket")
    }

    /// Actively discover WebSocket endpoints by probing common paths
    async fn discover_websocket_endpoints(&self, url: &str) -> Vec<String> {
        let mut discovered = Vec::new();

        // Parse base URL
        let base_url = if let Ok(parsed) = url::Url::parse(url) {
            let scheme = if parsed.scheme() == "https" {
                "wss"
            } else {
                "ws"
            };
            let host = parsed.host_str().unwrap_or("localhost");
            let port = if let Some(p) = parsed.port() {
                format!(":{}", p)
            } else {
                String::new()
            };
            format!("{}://{}{}", scheme, host, port)
        } else {
            return discovered;
        };

        // Common WebSocket endpoint paths
        let common_paths = vec![
            "/ws",
            "/wss",
            "/websocket",
            "/socket",
            "/socket.io",
            "/sockjs",
            "/api/ws",
            "/api/websocket",
            "/realtime",
            "/live",
            "/chat",
            "/stream",
            "/events",
            "/notifications",
        ];

        // Try to connect to each common path
        for path in common_paths {
            let ws_url = format!("{}{}", base_url, path);

            // Try to establish WebSocket connection with a short timeout
            match timeout(Duration::from_secs(2), connect_async(&ws_url)).await {
                Ok(Ok((ws_stream, _response))) => {
                    debug!("[WebSocket Discovery] Found endpoint: {}", ws_url);
                    discovered.push(ws_url.clone());

                    // Close the connection
                    let (mut write, _) = ws_stream.split();
                    let _ = write.send(Message::Close(None)).await;
                }
                Ok(Err(e)) => {
                    // Connection failed, but check if it's an HTTP upgrade response
                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("upgrade") || error_str.contains("101") {
                        debug!("[WebSocket Discovery] Potential endpoint: {} (upgrade-related error)", ws_url);
                        discovered.push(ws_url);
                    }
                }
                Err(_) => {
                    // Timeout - skip
                }
            }
        }

        discovered
    }

    /// Check origin validation
    fn check_origin_validation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if code validates Origin header
        let checks_origin = body_lower.contains("origin")
            && (body_lower.contains("check")
                || body_lower.contains("validate")
                || body_lower.contains("verify")
                || body_lower.contains("allowed")
                || body_lower.contains("whitelist"));

        // Check for WebSocket upgrade without origin validation
        if (body_lower.contains("websocket") || body_lower.contains("upgrade")) && !checks_origin {
            vulnerabilities.push(self.create_vulnerability(
                "Missing WebSocket Origin Validation",
                url,
                Severity::High,
                Confidence::Medium,
                "WebSocket endpoint does not validate Origin header - vulnerable to CSWSH",
                "No Origin header validation detected in WebSocket code".to_string(),
                7.4,
            ));
        }
    }

    /// Check authentication
    fn check_authentication(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check if authentication is implemented
        let has_auth = body_lower.contains("authenticate")
            || body_lower.contains("authorization")
            || body_lower.contains("token")
            || body_lower.contains("session");

        // If WebSocket but no auth indicators
        if (body_lower.contains("websocket") || body_lower.contains("socket.io")) && !has_auth {
            vulnerabilities.push(self.create_vulnerability(
                "WebSocket Missing Authentication",
                url,
                Severity::Medium,
                Confidence::Low,
                "WebSocket endpoint may lack authentication - verify manually",
                "No authentication mechanisms detected in WebSocket code".to_string(),
                5.3,
            ));
        }
    }

    /// Test CSWSH (Cross-Site WebSocket Hijacking)
    async fn test_cswsh(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Try to upgrade to WebSocket with malicious origin
        // Note: This is simplified since we're using HTTP client, not WebSocket client
        self.http_client.get(url).await
    }

    /// Check CSWSH vulnerability
    fn check_cswsh(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check if WebSocket upgrade succeeded without proper origin check
        if response.status_code == 101
            || response.header("upgrade").is_some()
            || response.header("sec-websocket-accept").is_some()
        {
            vulnerabilities.push(self.create_vulnerability(
                "Cross-Site WebSocket Hijacking (CSWSH)",
                url,
                Severity::High,
                Confidence::Medium,
                "WebSocket accepts connections without proper origin validation",
                "WebSocket upgrade accepted without origin validation".to_string(),
                7.5,
            ));
        }
    }

    /// Check for sensitive data in WebSocket URL
    fn check_sensitive_data_in_url(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        let url_lower = url.to_lowercase();

        // Check for sensitive parameters in URL
        let sensitive_params = vec![
            "token=",
            "api_key=",
            "apikey=",
            "secret=",
            "password=",
            "session=",
            "auth=",
            "key=",
            "access_token=",
        ];

        for param in &sensitive_params {
            if url_lower.contains(param) {
                vulnerabilities.push(self.create_vulnerability(
                    "Sensitive Data in WebSocket URL",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "WebSocket URL contains sensitive data - vulnerable to leakage via logs/referrer",
                    format!("Sensitive parameter '{}' found in WebSocket URL", param),
                    6.5,
                ));
                break;
            }
        }

        // Check for insecure ws:// instead of wss://
        if url.starts_with("ws://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
            vulnerabilities.push(self.create_vulnerability(
                "WebSocket Using Insecure Protocol",
                url,
                Severity::Medium,
                Confidence::High,
                "WebSocket uses unencrypted ws:// protocol - data transmitted in plaintext",
                "WebSocket URL uses ws:// instead of wss://".to_string(),
                5.9,
            ));
        }
    }

    /// Check message injection vulnerabilities
    fn check_message_injection(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check if messages are processed without validation
        let validates_messages = body.contains("validate")
            || body.contains("sanitize")
            || body.contains("escape")
            || body.contains("filter");

        let processes_messages = body.contains("onmessage")
            || body.contains("on('message")
            || body.contains("addEventListener('message");

        if processes_messages && !validates_messages {
            vulnerabilities.push(self.create_vulnerability(
                "WebSocket Message Injection Risk",
                url,
                Severity::Medium,
                Confidence::Low,
                "WebSocket messages may not be validated - potential injection attacks",
                "Message processing without apparent validation detected".to_string(),
                5.0,
            ));
        }
    }

    /// Check rate limiting
    fn check_rate_limiting(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for rate limiting implementation
        let has_rate_limit = body_lower.contains("rate")
            || body_lower.contains("throttle")
            || body_lower.contains("limit")
            || body_lower.contains("quota");

        if (body_lower.contains("websocket") || body_lower.contains("socket")) && !has_rate_limit {
            vulnerabilities.push(self.create_vulnerability(
                "WebSocket Missing Rate Limiting",
                url,
                Severity::Low,
                Confidence::Low,
                "WebSocket endpoint may lack rate limiting - vulnerable to DoS",
                "No rate limiting implementation detected".to_string(),
                4.3,
            ));
        }
    }

    /// Check WebSocket Sec headers
    fn check_sec_headers(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check for proper Sec-WebSocket headers in upgrade response
        if response.header("upgrade").is_some() {
            if response.header("sec-websocket-accept").is_none() {
                vulnerabilities.push(self.create_vulnerability(
                    "Missing Sec-WebSocket-Accept Header",
                    url,
                    Severity::Low,
                    Confidence::High,
                    "WebSocket upgrade response missing Sec-WebSocket-Accept header",
                    "Required security header not present in upgrade response".to_string(),
                    3.7,
                ));
            }
        }
    }

    /// Convert HTTP(S) URL to WebSocket URL
    fn convert_to_ws_url(&self, url: &str) -> Option<String> {
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return Some(url.to_string());
        }

        // Try common WebSocket endpoint patterns
        let base = if url.starts_with("https://") {
            url.replace("https://", "wss://")
        } else if url.starts_with("http://") {
            url.replace("http://", "ws://")
        } else {
            return None;
        };

        // Try common WebSocket paths
        let paths = vec![
            "/ws",
            "/wss",
            "/websocket",
            "/socket.io",
            "/sockjs",
            "/socket",
            "/chat",
            "/realtime",
            "/live",
            "/api/ws",
            "/api/websocket",
        ];

        // If URL already has a path that looks like WebSocket, use it
        for ws_path in &paths {
            if url.contains(ws_path) {
                return Some(base);
            }
        }

        // Otherwise, try appending common paths
        Some(format!("{}/ws", base.trim_end_matches('/')))
    }

    /// Test WebSocket CSRF - sensitive commands without authentication
    async fn test_websocket_csrf(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let marker = uuid::Uuid::new_v4().to_string();

        info!("[WebSocket CSRF] Testing: {}", ws_url);

        // Try to connect WITHOUT cookies/auth
        let connect_result = timeout(Duration::from_secs(5), connect_async(ws_url)).await;

        let ws_stream = match connect_result {
            Ok(Ok((stream, response))) => {
                debug!(
                    "[WebSocket CSRF] Connected successfully: {:?}",
                    response.status()
                );

                // If connection succeeds without authentication, that's already a vulnerability
                if response.status().is_success() || response.status().as_u16() == 101 {
                    vulnerabilities.push(self.create_vulnerability(
                        "WebSocket Connection Without Authentication",
                        ws_url,
                        Severity::High,
                        Confidence::High,
                        "WebSocket accepts connections without authentication tokens or cookies",
                        format!(
                            "Connected to WebSocket without credentials. Status: {}",
                            response.status()
                        ),
                        7.5,
                    ));
                }

                stream
            }
            Ok(Err(e)) => {
                debug!("[WebSocket CSRF] Connection failed: {}", e);
                return Ok(vulnerabilities);
            }
            Err(_) => {
                debug!("[WebSocket CSRF] Connection timeout");
                return Ok(vulnerabilities);
            }
        };

        let (mut write, mut read) = ws_stream.split();

        // Test privileged commands that should require authentication
        let test_payloads = vec![
            format!(r#"{{"action":"deleteUser","userId":"1","marker":"ws_{marker}"}}"#),
            format!(
                r#"{{"action":"updateProfile","email":"attacker@evil.com","marker":"ws_{marker}"}}"#
            ),
            format!(r#"{{"action":"transferFunds","amount":1000,"marker":"ws_{marker}"}}"#),
            format!(r#"{{"command":"admin","operation":"delete","marker":"ws_{marker}"}}"#),
            format!(r#"{{"type":"privileged","action":"execute","marker":"ws_{marker}"}}"#),
        ];

        for payload in &test_payloads {
            // Send privileged command
            if let Err(e) = write.send(Message::Text(payload.clone().into())).await {
                debug!("[WebSocket CSRF] Failed to send: {}", e);
                break;
            }

            // Try to read response
            if let Ok(Some(msg_result)) = timeout(Duration::from_millis(500), read.next()).await {
                if let Ok(msg) = msg_result {
                    let response_text = msg.to_text().unwrap_or("");

                    // Check if command was executed (look for success indicators)
                    if (response_text.contains("success")
                        || response_text.contains("executed")
                        || response_text.contains("completed")
                        || response_text.contains(&marker))
                        && !response_text.contains("unauthorized")
                        && !response_text.contains("forbidden")
                        && !response_text.contains("error")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket CSRF - Unauthenticated Command Execution",
                            ws_url,
                            Severity::Critical,
                            Confidence::High,
                            "WebSocket accepts privileged commands without authentication",
                            format!("Payload: {}\nResponse: {}", payload, response_text),
                            9.1,
                        ));
                        break; // Found vulnerability, no need to test more
                    }
                }
            }
        }

        // Close connection
        let _ = write.send(Message::Close(None)).await;

        Ok(vulnerabilities)
    }

    /// Test WebSocket Message Injection
    async fn test_message_injection(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let marker = uuid::Uuid::new_v4().to_string();

        info!("[WebSocket Injection] Testing: {}", ws_url);

        let connect_result = timeout(Duration::from_secs(5), connect_async(ws_url)).await;

        let (ws_stream, _) = match connect_result {
            Ok(Ok((stream, response))) => (stream, response),
            _ => return Ok(vulnerabilities),
        };

        let (mut write, mut read) = ws_stream.split();

        // Test XSS in WebSocket messages
        let xss_payloads = vec![
            format!(r#"{{"message":"<script>alert('ws_{marker}')</script>"}}"#),
            format!(r#"{{"text":"<img src=x onerror=alert('ws_{marker}')>"}}"#),
            format!(r#"{{"content":"<svg onload=alert('ws_{marker}')>"}}"#),
            format!(r#"{{"data":"javascript:alert('ws_{marker}')"}}"#),
        ];

        for payload in &xss_payloads {
            if let Ok(_) = write.send(Message::Text(payload.clone().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check if payload is reflected without sanitization
                    if response.contains("<script>")
                        || response.contains("onerror=")
                        || response.contains("onload=")
                        || response.contains("javascript:")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket XSS - Unsanitized Message Reflection",
                            ws_url,
                            Severity::High,
                            Confidence::High,
                            "WebSocket reflects messages without sanitization - XSS possible",
                            format!("Payload: {}\nReflected: {}", payload, response),
                            7.8,
                        ));
                        break;
                    }
                }
            }
        }

        // Test SQL Injection
        let sql_payloads = vec![
            format!(r#"{{"search":"' OR 1=1-- ws_{marker}"}}"#),
            format!(r#"{{"query":"' UNION SELECT NULL-- ws_{marker}"}}"#),
            format!(r#"{{"filter":"1'; DROP TABLE users-- ws_{marker}"}}"#),
        ];

        for payload in &sql_payloads {
            if let Ok(_) = write.send(Message::Text(payload.clone().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check for SQL error messages
                    if response.contains("SQL")
                        || response.contains("syntax error")
                        || response.contains("mysql")
                        || response.contains("postgresql")
                        || response.contains("sqlite")
                        || response.contains("ORA-")
                        || response.contains("syntax")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket SQL Injection",
                            ws_url,
                            Severity::Critical,
                            Confidence::High,
                            "WebSocket message processing vulnerable to SQL injection",
                            format!("Payload: {}\nError: {}", payload, response),
                            9.8,
                        ));
                        break;
                    }
                }
            }
        }

        // Test Command Injection
        let cmd_payloads = vec![
            format!(r#"{{"ping":"127.0.0.1; whoami ws_{marker}"}}"#),
            format!(r#"{{"host":"localhost && id ws_{marker}"}}"#),
            format!(r#"{{"cmd":"test | ls ws_{marker}"}}"#),
        ];

        for payload in &cmd_payloads {
            if let Ok(_) = write.send(Message::Text(payload.clone().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check for command execution indicators
                    if response.contains("uid=")
                        || response.contains("gid=")
                        || response.contains("root")
                        || response.contains("/bin/")
                        || response.contains("total ")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket Command Injection",
                            ws_url,
                            Severity::Critical,
                            Confidence::High,
                            "WebSocket message processing vulnerable to command injection",
                            format!("Payload: {}\nOutput: {}", payload, response),
                            9.8,
                        ));
                        break;
                    }
                }
            }
        }

        let _ = write.send(Message::Close(None)).await;
        Ok(vulnerabilities)
    }

    /// Test WebSocket Origin Bypass (Cross-Site WebSocket Hijacking)
    async fn test_origin_bypass(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        info!("[WebSocket Origin] Testing: {}", ws_url);

        // Test with malicious origins - comprehensive list
        let evil_origins = vec![
            "https://evil.com",
            "http://attacker.evil",
            "https://attacker.com",
            "http://malicious.net",
            "null",
            "",
            "file://",
            "data://",
            "javascript://evil.com",
        ];

        for origin in &evil_origins {
            // Create custom request with Origin header
            let request = match url::Url::parse(ws_url) {
                Ok(parsed_url) => {
                    let host = parsed_url.host_str().unwrap_or("localhost");
                    let _path = parsed_url.path();

                    let mut request = tungstenite::handshake::client::Request::builder()
                        .uri(ws_url)
                        .header("Host", host)
                        .header("Connection", "Upgrade")
                        .header("Upgrade", "websocket")
                        .header("Sec-WebSocket-Version", "13")
                        .header(
                            "Sec-WebSocket-Key",
                            tungstenite::handshake::client::generate_key(),
                        );

                    if !origin.is_empty() {
                        request = request.header("Origin", *origin);
                    }

                    match request.body(()) {
                        Ok(req) => req,
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            };

            // Try to connect with malicious origin
            let connect_result = timeout(Duration::from_secs(5), connect_async(request)).await;

            if let Ok(Ok((ws_stream, response))) = connect_result {
                // Connection accepted with malicious origin
                let origin_display = if origin.is_empty() {
                    "no origin"
                } else {
                    origin
                };

                vulnerabilities.push(self.create_vulnerability(
                    "WebSocket Origin Validation Bypass",
                    ws_url,
                    Severity::High,
                    Confidence::High,
                    &format!(
                        "WebSocket accepts connections from malicious origin: {}",
                        origin_display
                    ),
                    format!(
                        "Connected with Origin: {}\nStatus: {}",
                        origin_display,
                        response.status()
                    ),
                    7.5,
                ));

                // Close the connection
                let (mut write, _) = ws_stream.split();
                let _ = write.send(Message::Close(None)).await;

                break; // Found vulnerability
            }
        }

        Ok(vulnerabilities)
    }

    /// Test WebSocket Hijacking
    async fn test_websocket_hijacking(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        info!("[WebSocket Hijacking] Testing: {}", ws_url);

        // Check if WebSocket URL contains tokens (security issue)
        let url_lower = ws_url.to_lowercase();
        let sensitive_params = vec!["token=", "session=", "key=", "auth=", "api_key="];

        for param in &sensitive_params {
            if url_lower.contains(param) {
                vulnerabilities.push(self.create_vulnerability(
                    "WebSocket Session Token in URL",
                    ws_url,
                    Severity::High,
                    Confidence::High,
                    "WebSocket URL contains authentication token - vulnerable to hijacking via logs",
                    format!("Sensitive parameter '{}' found in URL", param),
                    7.5,
                ));
            }
        }

        // Test if WebSocket uses predictable connection IDs
        let connect_result = timeout(Duration::from_secs(5), connect_async(ws_url)).await;

        if let Ok(Ok((ws_stream, _))) = connect_result {
            let (mut write, mut read) = ws_stream.split();

            // Send a test message to see if we get a connection ID
            let test_msg = r#"{"type":"test","action":"getId"}"#;
            if let Ok(_) = write.send(Message::Text(test_msg.to_string().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check for sequential or predictable IDs
                    if response.contains("\"id\":")
                        || response.contains("\"connectionId\":")
                        || response.contains("\"sessId\":")
                    {
                        // Try to extract the ID pattern
                        if response.contains("\"id\":1")
                            || response.contains("\"id\":\"1\"")
                            || response.contains("\"id\":12")
                            || response.contains("\"id\":123")
                        {
                            vulnerabilities.push(self.create_vulnerability(
                                "WebSocket Predictable Connection IDs",
                                ws_url,
                                Severity::Medium,
                                Confidence::Medium,
                                "WebSocket uses predictable connection IDs - vulnerable to session hijacking",
                                format!("Response contains predictable ID: {}", response),
                                6.5,
                            ));
                        }
                    }
                }
            }

            let _ = write.send(Message::Close(None)).await;
        }

        Ok(vulnerabilities)
    }

    /// Test WebSocket Denial of Service (limited to prevent production impact)
    async fn test_websocket_dos(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        info!("[WebSocket DoS] Testing: {}", ws_url);

        let connect_result = timeout(Duration::from_secs(5), connect_async(ws_url)).await;

        let (ws_stream, _) = match connect_result {
            Ok(Ok((stream, response))) => (stream, response),
            _ => return Ok(vulnerabilities),
        };

        let (mut write, mut read) = ws_stream.split();

        // Test 1: Large message (1MB, not 10MB to be safe)
        let large_payload = "A".repeat(1024 * 1024); // 1MB
        let large_msg = format!(r#"{{"data":"{}"}}"#, large_payload);

        let start = std::time::Instant::now();
        if let Ok(_) = write.send(Message::Text(large_msg.clone().into())).await {
            if let Ok(Some(Ok(msg))) = timeout(Duration::from_secs(3), read.next()).await {
                let duration = start.elapsed();
                let response = msg.to_text().unwrap_or("");

                // If server accepts and processes large message without error
                if !response.contains("error")
                    && !response.contains("too large")
                    && !response.contains("limit exceeded")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "WebSocket Large Message DoS",
                        ws_url,
                        Severity::Medium,
                        Confidence::High,
                        "WebSocket accepts extremely large messages without size limits",
                        format!("Sent 1MB message, processed in {:?}", duration),
                        5.3,
                    ));
                }
            }
        }

        // Test 2: Rapid small messages (limit to 50 to be safe, not 1000)
        let mut rapid_success = 0;
        let start = std::time::Instant::now();

        for i in 0..50 {
            let msg = format!(r#"{{"seq":{}}}"#, i);
            if write.send(Message::Text(msg.into())).await.is_ok() {
                rapid_success += 1;
            } else {
                break;
            }
        }

        let duration = start.elapsed();

        if rapid_success >= 45 && duration.as_millis() < 1000 {
            vulnerabilities.push(self.create_vulnerability(
                "WebSocket Rate Limiting Missing",
                ws_url,
                Severity::Medium,
                Confidence::High,
                "WebSocket accepts rapid messages without rate limiting - DoS possible",
                format!(
                    "Sent {} messages in {:?} without rejection",
                    rapid_success, duration
                ),
                6.5,
            ));
        }

        // Test 3: Malformed frames
        let malformed_payloads = vec![
            "{invalid json",
            "not json at all",
            "[]]]",
            r#"{"unclosed": "#,
        ];

        for payload in &malformed_payloads {
            if let Ok(_) = write.send(Message::Text(payload.to_string().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check for crash indicators or verbose errors
                    if response.contains("panic")
                        || response.contains("exception")
                        || response.contains("stack trace")
                        || response.contains("internal error")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket Malformed Message Crash",
                            ws_url,
                            Severity::Medium,
                            Confidence::High,
                            "WebSocket crashes or leaks internal errors on malformed messages",
                            format!("Payload: {}\nError: {}", payload, response),
                            5.0,
                        ));
                        break;
                    }
                }
            }
        }

        let _ = write.send(Message::Close(None)).await;
        Ok(vulnerabilities)
    }

    /// Test WebSocket Protocol Confusion
    async fn test_protocol_confusion(&self, ws_url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        info!("[WebSocket Protocol] Testing: {}", ws_url);

        let connect_result = timeout(Duration::from_secs(5), connect_async(ws_url)).await;

        let (ws_stream, _) = match connect_result {
            Ok(Ok((stream, response))) => (stream, response),
            _ => return Ok(vulnerabilities),
        };

        let (mut write, mut read) = ws_stream.split();

        // Test 1: Send HTTP-like request over WebSocket
        let http_payloads = vec![
            "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            "POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ];

        for payload in &http_payloads {
            if let Ok(_) = write.send(Message::Text(payload.to_string().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check if HTTP request was processed
                    if response.contains("HTTP/")
                        || response.contains("200 OK")
                        || response.contains("Content-Type")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket Protocol Confusion - HTTP Processing",
                            ws_url,
                            Severity::Medium,
                            Confidence::High,
                            "WebSocket processes HTTP requests - protocol confusion possible",
                            format!("Sent: {}\nResponse: {}", payload, response),
                            6.0,
                        ));
                        break;
                    }
                }
            }
        }

        // Test 2: Non-JSON data when JSON expected
        let non_json_payloads = vec![
            "plain text message",
            "<xml><tag>value</tag></xml>",
            "random binary data \x00\x01\x02",
        ];

        for payload in &non_json_payloads {
            if let Ok(_) = write.send(Message::Text(payload.to_string().into())).await {
                if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                    let response = msg.to_text().unwrap_or("");

                    // Check for verbose error disclosure
                    if response.contains("JSON.parse")
                        || response.contains("unexpected token")
                        || response.contains("SyntaxError")
                        || response.contains("at position")
                        || response.contains("line ")
                        || response.contains("column ")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "WebSocket Verbose Error Disclosure",
                            ws_url,
                            Severity::Low,
                            Confidence::High,
                            "WebSocket returns verbose errors that may leak implementation details",
                            format!("Payload: {}\nError: {}", payload, response),
                            4.3,
                        ));
                        break;
                    }
                }
            }
        }

        // Test 3: Binary frames when text expected
        if let Ok(_) = write
            .send(Message::Binary(vec![0x00, 0x01, 0x02, 0xFF].into()))
            .await
        {
            if let Ok(Some(Ok(msg))) = timeout(Duration::from_millis(500), read.next()).await {
                let response_str = format!("{:?}", msg);

                // Check if binary data is processed without validation
                if !response_str.contains("error") && !response_str.contains("invalid") {
                    vulnerabilities.push(self.create_vulnerability(
                        "WebSocket Binary Frame Processing",
                        ws_url,
                        Severity::Low,
                        Confidence::Medium,
                        "WebSocket processes binary frames without proper validation",
                        format!("Binary frame accepted: {:?}", msg),
                        3.7,
                    ));
                }
            }
        }

        let _ = write.send(Message::Close(None)).await;
        Ok(vulnerabilities)
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("websocket_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("WebSocket Vulnerability - {}", title),
            severity,
            confidence,
            category: "WebSocket Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-346".to_string(), // Origin Validation Error
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Implement Strict Origin Validation**
   ```javascript
   // Node.js WebSocket server
   const WebSocket = require('ws');
   const wss = new WebSocket.Server({ noServer: true });

   const ALLOWED_ORIGINS = [
     'https://app.example.com',
     'https://www.example.com'
   ];

   server.on('upgrade', (request, socket, head) => {
     const origin = request.headers.origin;

     // Validate origin
     if (!ALLOWED_ORIGINS.includes(origin)) {
       socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
       socket.destroy();
       return;
     }

     wss.handleUpgrade(request, socket, head, (ws) => {
       wss.emit('connection', ws, request);
     });
   });
   ```

2. **Implement Authentication & Authorization**
   ```javascript
   // Authenticate during handshake
   server.on('upgrade', async (request, socket, head) => {
     const token = new URLSearchParams(request.url.split('?')[1]).get('token');

     // Validate token
     const user = await validateToken(token);
     if (!user) {
       socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
       socket.destroy();
       return;
     }

     wss.handleUpgrade(request, socket, head, (ws) => {
       ws.user = user;  // Attach user to connection
       wss.emit('connection', ws, request);
     });
   });

   // Authorize individual messages
   ws.on('message', (message) => {
     const data = JSON.parse(message);

     if (!canPerformAction(ws.user, data.action)) {
       ws.send(JSON.stringify({ error: 'Unauthorized' }));
       return;
     }

     // Process message
   });
   ```

3. **Use Secure WebSocket (wss://)**
   ```javascript
   // Use TLS for WebSocket connections
   const https = require('https');
   const fs = require('fs');

   const server = https.createServer({
     cert: fs.readFileSync('cert.pem'),
     key: fs.readFileSync('key.pem')
   });

   const wss = new WebSocket.Server({ server });

   // Client connects with wss://
   const ws = new WebSocket('wss://example.com/socket');
   ```

4. **Validate and Sanitize All Messages**
   ```javascript
   // Input validation
   const Joi = require('joi');

   const messageSchema = Joi.object({
     type: Joi.string().valid('chat', 'notification').required(),
     content: Joi.string().max(1000).required(),
     metadata: Joi.object()
   });

   ws.on('message', (message) => {
     let data;
     try {
       data = JSON.parse(message);
     } catch (e) {
       ws.send(JSON.stringify({ error: 'Invalid JSON' }));
       return;
     }

     // Validate schema
     const { error } = messageSchema.validate(data);
     if (error) {
       ws.send(JSON.stringify({ error: error.message }));
       return;
     }

     // Sanitize content
     data.content = sanitizeHtml(data.content);

     // Process validated message
     processMessage(ws, data);
   });
   ```

5. **Implement Rate Limiting**
   ```javascript
   const rateLimit = require('ws-rate-limit');

   // Limit to 100 messages per minute per connection
   const limiter = rateLimit('100 per minute');

   ws.on('message', async (message) => {
     try {
       await limiter.check(ws.id);
     } catch (error) {
       ws.send(JSON.stringify({ error: 'Rate limit exceeded' }));
       return;
     }

     // Process message
   });
   ```

6. **Prevent Token/Credential Leakage**
   ```javascript
   // WRONG - credentials in URL
   const ws = new WebSocket('wss://example.com?token=secret123');

   // CORRECT - use headers or post-connection auth
   const ws = new WebSocket('wss://example.com');
   ws.onopen = () => {
     ws.send(JSON.stringify({
       type: 'auth',
       token: getTokenFromSecureStorage()
     }));
   };
   ```

7. **Implement Connection Limits**
   ```javascript
   const connectedClients = new Map();
   const MAX_CONNECTIONS_PER_USER = 5;

   wss.on('connection', (ws, request) => {
     const userId = ws.user.id;

     // Check connection limit
     const userConnections = connectedClients.get(userId) || [];
     if (userConnections.length >= MAX_CONNECTIONS_PER_USER) {
       ws.close(1008, 'Too many connections');
       return;
     }

     // Track connection
     userConnections.push(ws);
     connectedClients.set(userId, userConnections);

     ws.on('close', () => {
       // Remove from tracking
       const connections = connectedClients.get(userId);
       const index = connections.indexOf(ws);
       if (index > -1) {
         connections.splice(index, 1);
       }
     });
   });
   ```

8. **Use CSRF Tokens for WebSocket Handshake**
   ```javascript
   // Generate CSRF token on page load
   const csrfToken = generateCSRFToken();

   // Include in WebSocket connection
   const ws = new WebSocket(`wss://example.com?csrf=${csrfToken}`);

   // Server validates
   server.on('upgrade', (request, socket, head) => {
     const csrf = new URLSearchParams(request.url.split('?')[1]).get('csrf');

     if (!validateCSRF(csrf, request.headers.cookie)) {
       socket.destroy();
       return;
     }

     // Continue with upgrade
   });
   ```

9. **Implement Heartbeat/Ping-Pong**
   ```javascript
   // Detect and close dead connections
   function heartbeat() {
     this.isAlive = true;
   }

   wss.on('connection', (ws) => {
     ws.isAlive = true;
     ws.on('pong', heartbeat);
   });

   const interval = setInterval(() => {
     wss.clients.forEach((ws) => {
       if (ws.isAlive === false) {
         return ws.terminate();
       }
       ws.isAlive = false;
       ws.ping();
     });
   }, 30000);
   ```

10. **Security Checklist**
    - [ ] Origin header validated against whitelist
    - [ ] Authentication required for connections
    - [ ] Authorization checked per message
    - [ ] All connections use wss:// (TLS)
    - [ ] No credentials in WebSocket URL
    - [ ] All messages validated and sanitized
    - [ ] Rate limiting implemented
    - [ ] Connection limits per user
    - [ ] CSRF protection for handshake
    - [ ] Dead connection cleanup (heartbeat)
    - [ ] Error messages don't leak info
    - [ ] Comprehensive logging enabled

11. **Testing & Monitoring**
    - Test with tools like wsrepl, wsdump
    - Monitor for unauthorized connection attempts
    - Log all authentication failures
    - Alert on rate limit violations
    - Track connection patterns

References:
- OWASP WebSocket Security: https://owasp.org/www-community/vulnerabilities/WebSocket_security
- WebSocket RFC 6455: https://datatracker.ietf.org/doc/html/rfc6455
- PortSwigger WebSocket Security: https://portswigger.net/web-security/websockets
"#
            .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_websocket_detection() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"const ws = new WebSocket('wss://example.com/socket');"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.detect_websocket_endpoint(&response, "https://example.com"));
    }

    #[test]
    fn test_missing_origin_validation() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"const wss = new WebSocket.Server({ server });"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_origin_validation(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing origin validation");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_insecure_websocket_protocol() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_sensitive_data_in_url("ws://example.com/socket", &mut vulns);

        assert!(vulns.len() > 0, "Should detect insecure ws:// protocol");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_sensitive_data_in_url() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_sensitive_data_in_url("wss://example.com/socket?token=abc123", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect token in URL");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.detect_websocket_endpoint(&response, "https://example.com"));
    }

    #[test]
    fn test_websocket_url_detection() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        // Should detect ws:// URL
        assert!(scanner.detect_websocket_endpoint(&response, "ws://example.com/socket"));

        // Should detect wss:// URL
        assert!(scanner.detect_websocket_endpoint(&response, "wss://example.com/socket"));
    }

    #[test]
    fn test_convert_to_ws_url() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        // HTTPS should convert to WSS
        let ws_url = scanner.convert_to_ws_url("https://example.com/api/ws");
        assert!(ws_url.is_some());
        assert!(ws_url.unwrap().starts_with("wss://"));

        // HTTP should convert to WS
        let ws_url = scanner.convert_to_ws_url("http://example.com/socket");
        assert!(ws_url.is_some());
        assert!(ws_url.unwrap().starts_with("ws://"));

        // Already WebSocket URL should be preserved
        let ws_url = scanner.convert_to_ws_url("wss://example.com/chat");
        assert_eq!(ws_url, Some("wss://example.com/chat".to_string()));
    }

    #[test]
    fn test_sockjs_detection() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"const socket = new SockJS('/sockjs');"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.detect_websocket_endpoint(&response, "https://example.com"));
    }

    #[test]
    fn test_socket_io_detection() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"const socket = io.connect('http://localhost:3000');"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.detect_websocket_endpoint(&response, "http://localhost:3000"));
    }

    #[test]
    fn test_upgrade_header_detection() {
        let scanner = WebSocketScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("upgrade".to_string(), "websocket".to_string());

        let response = crate::http_client::HttpResponse {
            status_code: 101,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        assert!(scanner.detect_websocket_endpoint(&response, "https://example.com"));
    }
}
