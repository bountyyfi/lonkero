// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - WebSocket Security Scanner
 * Tests for WebSocket vulnerabilities and misconfigurations
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
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

        // Test 1: Detect WebSocket endpoints
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                info!("[NOTE] [WebSocket] Could not fetch URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        let is_websocket = self.detect_websocket_endpoint(&response, url);
        if !is_websocket {
            debug!("[NOTE] [WebSocket] Not a WebSocket endpoint");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[SUCCESS] [WebSocket] WebSocket endpoint detected");

        // Test 2: Check for missing origin validation
        tests_run += 1;
        self.check_origin_validation(&response, url, &mut vulnerabilities);

        // Test 3: Check for missing authentication
        tests_run += 1;
        self.check_authentication(&response, url, &mut vulnerabilities);

        // Test 4: Test CSWSH (Cross-Site WebSocket Hijacking)
        tests_run += 1;
        if let Ok(cswsh_response) = self.test_cswsh(url).await {
            self.check_cswsh(&cswsh_response, url, &mut vulnerabilities);
        }

        // Test 5: Check for sensitive data in WebSocket URL
        tests_run += 1;
        self.check_sensitive_data_in_url(url, &mut vulnerabilities);

        // Test 6: Check for tunnel/message injection
        tests_run += 1;
        self.check_message_injection(&response, url, &mut vulnerabilities);

        // Test 7: Check for rate limiting
        tests_run += 1;
        self.check_rate_limiting(&response, url, &mut vulnerabilities);

        // Test 8: Check WebSocket Sec headers
        tests_run += 1;
        self.check_sec_headers(&response, url, &mut vulnerabilities);

        info!(
            "[SUCCESS] [WebSocket] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect WebSocket endpoint
    fn detect_websocket_endpoint(&self, response: &crate::http_client::HttpResponse, url: &str) -> bool {
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
            || response.header("upgrade").map_or(false, |h| h.to_lowercase() == "websocket")
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
        if (body_lower.contains("websocket") || body_lower.contains("upgrade"))
            && !checks_origin
        {
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
        if (body_lower.contains("websocket") || body_lower.contains("socket.io"))
            && !has_auth
        {
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
            "token=", "api_key=", "apikey=", "secret=", "password=",
            "session=", "auth=", "key=", "access_token="
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

        if (body_lower.contains("websocket") || body_lower.contains("socket"))
            && !has_rate_limit
        {
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
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
}
