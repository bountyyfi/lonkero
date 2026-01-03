// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::{Context, Result};
use moka::future::Cache;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::analysis::{
    ErrorType, IntelligenceBus, PatternType, ResponseAnalyzer, SecurityIndicator,
};
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::rate_limiter::AdaptiveRateLimiter;

/// Realistic browser User-Agents to avoid detection
const BROWSER_USER_AGENTS: &[&str] = &[
    // Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    // Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    // Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    // Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    // Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

/// Get a realistic browser User-Agent (rotates to avoid blocks)
fn get_browser_user_agent() -> &'static str {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let index = COUNTER.fetch_add(1, Ordering::Relaxed) % BROWSER_USER_AGENTS.len();
    BROWSER_USER_AGENTS[index]
}

/// Maximum response body size (10MB) to prevent memory exhaustion
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Optimized connection pool settings for high throughput
const DEFAULT_POOL_IDLE_PER_HOST: usize = 32;
const DEFAULT_POOL_MAX_IDLE_TIMEOUT: u64 = 90;

#[derive(Clone)]
pub struct HttpClient {
    client: Arc<Client>,
    timeout: Duration,
    max_retries: u32,
    rate_limiter: Option<Arc<AdaptiveRateLimiter>>,
    cache: Option<Arc<Cache<String, HttpResponse>>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    max_body_size: usize,
    /// Optional response analyzer for semantic understanding
    response_analyzer: Option<Arc<ResponseAnalyzer>>,
    /// Optional intelligence bus for broadcasting findings
    intelligence_bus: Option<Arc<IntelligenceBus>>,
}

impl HttpClient {
    pub fn new(timeout_secs: u64, max_retries: u32) -> Result<Self> {
        Self::with_config(timeout_secs, max_retries, false, false, 0, 0)
    }

    pub fn with_config(
        timeout_secs: u64,
        max_retries: u32,
        http2_enabled: bool,
        http2_adaptive_window: bool,
        _http2_max_concurrent_streams: usize,
        pool_max_idle_per_host: usize,
    ) -> Result<Self> {
        let pool_idle = if pool_max_idle_per_host > 0 {
            pool_max_idle_per_host
        } else {
            DEFAULT_POOL_IDLE_PER_HOST
        };

        // CRITICAL SECURITY: Certificate validation configuration
        // This setting controls whether the HTTP client accepts invalid/self-signed SSL certificates
        //
        // PRODUCTION: Must be false (default) - rejects invalid certificates
        // DEV/TESTING: Can be set to true via ACCEPT_INVALID_CERTS=true environment variable
        //              for testing against self-signed certificates only
        //
        // Security implications of setting to true:
        // - Disables certificate chain validation
        // - Allows man-in-the-middle (MITM) attacks
        // - Bypasses hostname verification
        // - Should NEVER be true in production environments
        let accept_invalid_certs = std::env::var("ACCEPT_INVALID_CERTS")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false); // Default to false for security

        // SECURITY WARNING: Alert when running in insecure mode
        if accept_invalid_certs {
            eprintln!("\n========================================");
            eprintln!("WARNING: INSECURE MODE ENABLED!");
            eprintln!("========================================");
            eprintln!("Certificate validation is DISABLED!");
            eprintln!("This makes the scanner vulnerable to MITM attacks.");
            eprintln!("NEVER use this in production environments.");
            eprintln!("Only for dev/testing with self-signed certificates.");
            eprintln!("========================================\n");
        }

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(accept_invalid_certs)
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(get_browser_user_agent())
            .pool_max_idle_per_host(pool_idle)
            .pool_idle_timeout(Duration::from_secs(DEFAULT_POOL_MAX_IDLE_TIMEOUT))
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true);

        // Enable HTTP/2 optimizations if configured
        // Note: Don't use http2_prior_knowledge() as it breaks HTTPS/ALPN negotiation
        if http2_enabled {
            client_builder = client_builder
                .http2_adaptive_window(http2_adaptive_window)
                .http2_keep_alive_interval(Duration::from_secs(10))
                .http2_keep_alive_timeout(Duration::from_secs(20));
        }

        let client = client_builder
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client: Arc::new(client),
            timeout: Duration::from_secs(timeout_secs),
            max_retries,
            rate_limiter: None,
            cache: None,
            circuit_breaker: None,
            max_body_size: MAX_BODY_SIZE,
            response_analyzer: None,
            intelligence_bus: None,
        })
    }

    /// Set rate limiter for this client
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<AdaptiveRateLimiter>) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Enable response caching
    pub fn with_cache(mut self, max_capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        self.cache = Some(Arc::new(cache));
        self
    }

    /// Enable circuit breaker for fault tolerance
    pub fn with_circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.circuit_breaker = Some(Arc::new(CircuitBreaker::new(config)));
        self
    }

    /// Enable response intelligence analysis
    ///
    /// When enabled, every HTTP response will be analyzed for semantic meaning
    /// (SQL errors, stack traces, WAF detection, auth states, etc.) and findings
    /// will be broadcast to the IntelligenceBus for other scanners to consume.
    ///
    /// # Arguments
    /// * `response_analyzer` - The analyzer for extracting semantic meaning from responses
    /// * `intelligence_bus` - The bus for broadcasting findings to other scanners
    ///
    /// # Example
    /// ```ignore
    /// use std::sync::Arc;
    /// use lonkero::analysis::{ResponseAnalyzer, IntelligenceBus};
    /// use lonkero::http_client::HttpClient;
    ///
    /// let analyzer = Arc::new(ResponseAnalyzer::new());
    /// let bus = Arc::new(IntelligenceBus::new());
    /// let client = HttpClient::new(30, 3)?
    ///     .with_intelligence(analyzer, bus);
    /// ```
    pub fn with_intelligence(
        mut self,
        response_analyzer: Arc<ResponseAnalyzer>,
        intelligence_bus: Arc<IntelligenceBus>,
    ) -> Self {
        self.response_analyzer = Some(response_analyzer);
        self.intelligence_bus = Some(intelligence_bus);
        self
    }

    /// Set response analyzer without intelligence bus
    ///
    /// Useful when you want to analyze responses without broadcasting findings.
    pub fn with_response_analyzer(mut self, response_analyzer: Arc<ResponseAnalyzer>) -> Self {
        self.response_analyzer = Some(response_analyzer);
        self
    }

    /// Set intelligence bus
    ///
    /// Useful when adding a bus to a client that already has an analyzer.
    pub fn with_intelligence_bus(mut self, intelligence_bus: Arc<IntelligenceBus>) -> Self {
        self.intelligence_bus = Some(intelligence_bus);
        self
    }

    /// Analyze response for semantic meaning and broadcast findings
    ///
    /// This method performs non-blocking pattern matching on the response to detect:
    /// - SQL errors (with database type identification)
    /// - Stack traces (with framework detection)
    /// - WAF presence (with WAF type identification)
    /// - Authentication states
    /// - Sensitive data exposure
    ///
    /// Significant findings are broadcast to the IntelligenceBus for other scanners.
    async fn analyze_response_intelligence(&self, response: &HttpResponse) {
        let analyzer = match &self.response_analyzer {
            Some(a) => a,
            None => return,
        };

        // Perform semantic analysis
        let semantics = analyzer.analyze(response.status_code, &response.headers, &response.body);

        debug!(
            "Response analysis: type={:?}, auth={:?}, confidence={:.2}",
            semantics.response_type, semantics.auth_state, semantics.confidence
        );

        // Get the bus for broadcasting (if available)
        let bus = match &self.intelligence_bus {
            Some(b) => b,
            None => return,
        };

        // Broadcast WAF detection
        for indicator in &semantics.security_indicators {
            if let SecurityIndicator::WafPresent { waf_type } = indicator {
                debug!("WAF detected: {}", waf_type);
                bus.report_waf(waf_type, vec![]).await;
            }
        }

        // Broadcast SQL errors as vulnerability patterns
        if let Some(ref error_info) = semantics.error_info {
            if let ErrorType::Database { ref db_type } = error_info.error_type {
                let db_name = db_type.as_deref().unwrap_or("Unknown");
                debug!("SQL error detected: database type = {}", db_name);
                bus.report_vulnerability_pattern(
                    PatternType::SqlError,
                    &format!("Database type: {}", db_name),
                    None,
                )
                .await;
            }
        }

        // Broadcast stack trace detection
        if let Some(framework) = analyzer.has_stack_trace(&response.body) {
            debug!("Stack trace detected: framework = {}", framework);
            bus.report_vulnerability_pattern(
                PatternType::StackTrace,
                &format!("Framework: {}", framework),
                None,
            )
            .await;
        }

        // Broadcast debug mode detection
        if semantics
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::DebugMode))
        {
            debug!("Debug mode detected in response");
            bus.report_vulnerability_pattern(
                PatternType::DebugMode,
                "Debug mode appears to be enabled",
                None,
            )
            .await;
        }

        // Broadcast internal IP disclosure
        for exposure in &semantics.data_exposure {
            if matches!(
                exposure.exposure_type,
                crate::analysis::ExposureType::InternalIp
            ) {
                debug!("Internal IP disclosure detected");
                bus.report_vulnerability_pattern(
                    PatternType::InternalIp,
                    &format!("Internal IP exposed: {}", exposure.sample),
                    None,
                )
                .await;
            }
        }

        // Broadcast path disclosure
        for exposure in &semantics.data_exposure {
            if matches!(
                exposure.exposure_type,
                crate::analysis::ExposureType::FilePath
            ) {
                debug!("Path disclosure detected");
                bus.report_vulnerability_pattern(
                    PatternType::PathDisclosure,
                    &format!("File path exposed: {}", exposure.sample),
                    None,
                )
                .await;
            }
        }
    }

    /// Get the response analyzer if configured
    ///
    /// Returns a reference to the analyzer for external use when callers
    /// need to perform custom analysis or access analyzer methods directly.
    pub fn get_response_analyzer(&self) -> Option<&Arc<ResponseAnalyzer>> {
        self.response_analyzer.as_ref()
    }

    /// Get the intelligence bus if configured
    ///
    /// Returns a reference to the intelligence bus for external use when callers
    /// need to broadcast findings or subscribe to events directly.
    pub fn get_intelligence_bus(&self) -> Option<&Arc<IntelligenceBus>> {
        self.intelligence_bus.as_ref()
    }

    /// Analyze a response and return semantic information
    ///
    /// This is a public method that allows callers to get the full semantic
    /// analysis of a response without broadcasting to the intelligence bus.
    /// Useful for detailed analysis or when custom handling of findings is needed.
    ///
    /// Returns None if no response analyzer is configured.
    pub fn analyze_response(
        &self,
        response: &HttpResponse,
    ) -> Option<crate::analysis::ResponseSemantics> {
        self.response_analyzer.as_ref().map(|analyzer| {
            analyzer.analyze(response.status_code, &response.headers, &response.body)
        })
    }

    /// Send GET request with payload
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        // Periodic integrity verification (every 100 requests)
        let counter = crate::license::get_scan_counter();
        if counter > 0 && counter % 100 == 0 {
            if !crate::license::verify_rt_state() {
                return Err(anyhow::anyhow!("Request validation failed"));
            }
        }

        // Check circuit breaker first
        if let Some(cb) = &self.circuit_breaker {
            if !cb.is_request_allowed(url).await {
                return Err(anyhow::anyhow!("Circuit breaker is open for {}", url));
            }
        }

        // Check cache first
        if let Some(cache) = &self.cache {
            if let Some(cached_response) = cache.as_ref().get(url).await {
                return Ok(cached_response);
            }
        }

        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            match self.client.get(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();

                    // Clone headers once and optimize header map creation
                    let headers_map = {
                        let headers = response.headers();
                        let mut map = std::collections::HashMap::with_capacity(headers.len());
                        for (k, v) in headers.iter() {
                            if let Ok(value_str) = v.to_str() {
                                map.insert(k.as_str().to_string(), value_str.to_string());
                            }
                        }
                        map
                    };

                    // Read body with size limit
                    let body_bytes = response.bytes().await.unwrap_or_default();
                    let body = if body_bytes.len() > self.max_body_size {
                        // Truncate oversized responses
                        String::from_utf8_lossy(&body_bytes[..self.max_body_size]).to_string()
                    } else {
                        String::from_utf8_lossy(&body_bytes).to_string()
                    };

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;

                            // Also record circuit breaker failure
                            if let Some(cb) = &self.circuit_breaker {
                                cb.record_failure(url).await;
                            }

                            // Retry after backoff
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    // Record circuit breaker success
                    if let Some(cb) = &self.circuit_breaker {
                        if status.is_success() {
                            cb.record_success(url).await;
                        } else if status.is_server_error() {
                            cb.record_failure(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers_map,
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    // Store in cache if enabled
                    if let Some(cache) = &self.cache {
                        cache
                            .as_ref()
                            .insert(url.to_string(), http_response.clone())
                            .await;
                    }

                    return Ok(http_response);
                }
                Err(e) => {
                    // Record circuit breaker failure
                    if let Some(cb) = &self.circuit_breaker {
                        cb.record_failure(url).await;
                    }

                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send POST request with payload
    pub async fn post(&self, url: &str, body: String) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            match self
                .client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            // Retry after backoff
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send PUT request with payload
    pub async fn put(&self, url: &str, body: &str) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            match self
                .client
                .put(url)
                .header("Content-Type", "text/plain")
                .body(body.to_string())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send DELETE request
    pub async fn delete(&self, url: &str) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            match self.client.delete(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send POST request with custom headers
    pub async fn post_with_headers(
        &self,
        url: &str,
        body: &str,
        headers: Vec<(String, String)>,
    ) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            let mut request_builder = self.client.post(url);

            // Add custom headers
            for (key, value) in &headers {
                request_builder = request_builder.header(key, value);
            }

            match request_builder.body(body.to_string()).send().await {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let response_headers = response.headers().clone();
                    let response_body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            // Retry after backoff
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body: response_body,
                        headers: response_headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send POST request with JSON payload
    pub async fn post_json(&self, url: &str, json: &serde_json::Value) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;
        let body = json.to_string();

        while attempts <= self.max_retries {
            match self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "*/*")
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send POST request with form-encoded data
    pub async fn post_form(&self, url: &str, form_data: &str) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            match self
                .client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form_data.to_string())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            // Retry after backoff
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body,
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send GET request with custom headers
    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            let mut request_builder = self.client.get(url);

            // Add custom headers
            for (key, value) in &headers {
                request_builder = request_builder.header(key, value);
            }

            match request_builder.send().await {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let response_headers = response.headers().clone();
                    let response_body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            // Retry after backoff
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body: response_body,
                        headers: response_headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send request with custom HTTP method (e.g., PURGE, OPTIONS, PATCH)
    pub async fn request_with_method(&self, method: &str, url: &str) -> Result<HttpResponse> {
        // Wait for rate limiter slot if enabled
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait_for_slot(url).await?;
        }

        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.max_retries {
            let http_method =
                reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);

            match self.client.request(http_method, url).send().await {
                Ok(response) => {
                    let status = response.status();
                    let status_code = status.as_u16();
                    let response_headers = response.headers().clone();
                    let response_body = response.text().await.unwrap_or_default();

                    // Handle rate limiting responses
                    if let Some(limiter) = &self.rate_limiter {
                        if status_code == 429 || status_code == 503 {
                            limiter.record_rate_limit(url, status_code).await;
                            attempts += 1;
                            continue;
                        } else if status.is_success() {
                            limiter.record_success(url).await;
                        }
                    }

                    let http_response = HttpResponse {
                        status_code,
                        body: response_body,
                        headers: response_headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect(),
                        duration_ms: 0,
                    };

                    // Analyze response for intelligence (non-blocking pattern matching)
                    self.analyze_response_intelligence(&http_response).await;

                    return Ok(http_response);
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts <= self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }

    /// Send authenticated GET request using AuthSession
    pub async fn get_authenticated(
        &self,
        url: &str,
        auth: &crate::auth_context::AuthSession,
    ) -> Result<HttpResponse> {
        self.get_with_headers(url, auth.auth_headers()).await
    }

    /// Send authenticated POST request using AuthSession
    pub async fn post_authenticated(
        &self,
        url: &str,
        body: &str,
        auth: &crate::auth_context::AuthSession,
    ) -> Result<HttpResponse> {
        self.post_with_headers(url, body, auth.auth_headers()).await
    }

    /// Send authenticated POST request with content type using AuthSession
    pub async fn post_authenticated_with_content_type(
        &self,
        url: &str,
        body: &str,
        content_type: &str,
        auth: &crate::auth_context::AuthSession,
    ) -> Result<HttpResponse> {
        let mut headers = auth.auth_headers();
        headers.push(("Content-Type".to_string(), content_type.to_string()));
        self.post_with_headers(url, body, headers).await
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: String,
    pub headers: std::collections::HashMap<String, String>,
    pub duration_ms: u64,
}

impl HttpResponse {
    pub fn contains(&self, pattern: &str) -> bool {
        self.body.contains(pattern)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(&name.to_lowercase()).cloned()
    }
}
