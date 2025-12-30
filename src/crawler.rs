// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Web Crawler Module
 * Discovers attack surfaces: forms, inputs, APIs, links
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::rate_limiter::{AdaptiveRateLimiter, RateLimiterConfig};
use anyhow::{Context, Result};
use scraper::{Html, Selector};
use std::collections::{HashSet, HashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

/// Discovered form on a webpage
#[derive(Debug, Clone)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
    pub discovered_at: String,
}

impl DiscoveredForm {
    /// Generate a hash signature for deduplication
    pub fn signature(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.action.hash(&mut hasher);
        self.method.hash(&mut hasher);

        // Sort input names for consistent hashing
        let mut names: Vec<_> = self.inputs.iter().map(|i| &i.name).collect();
        names.sort();
        for name in names {
            name.hash(&mut hasher);
        }

        hasher.finish()
    }
}

/// Form input field
#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
    /// For SELECT elements - available options
    pub options: Option<Vec<String>>,
    /// Whether field is required
    pub required: bool,
}

/// Discovered JavaScript file
#[derive(Debug, Clone)]
pub struct DiscoveredScript {
    pub url: String,
    pub content: String,
}

/// Crawl results containing all discovered attack surfaces
#[derive(Debug, Clone)]
pub struct CrawlResults {
    pub forms: Vec<DiscoveredForm>,
    pub links: HashSet<String>,
    pub scripts: Vec<DiscoveredScript>,
    pub parameters: HashMap<String, HashSet<String>>, // endpoint -> parameter names
    pub api_endpoints: HashSet<String>,
    pub crawled_urls: HashSet<String>,
    /// True if site appears to be a client-side rendered SPA (React/Vue/Angular/Nuxt)
    pub is_spa: bool,
}

impl CrawlResults {
    pub fn new() -> Self {
        Self {
            forms: Vec::new(),
            links: HashSet::new(),
            scripts: Vec::new(),
            parameters: HashMap::new(),
            api_endpoints: HashSet::new(),
            crawled_urls: HashSet::new(),
            is_spa: false,
        }
    }

    /// Merge another CrawlResults into this one
    pub fn merge(&mut self, other: CrawlResults) {
        self.forms.extend(other.forms);
        self.links.extend(other.links);
        self.scripts.extend(other.scripts);
        self.crawled_urls.extend(other.crawled_urls);
        self.api_endpoints.extend(other.api_endpoints);
        self.is_spa = self.is_spa || other.is_spa;

        for (endpoint, params) in other.parameters {
            self.parameters.entry(endpoint).or_insert_with(HashSet::new).extend(params);
        }
    }

    /// Get all unique parameter names discovered
    pub fn get_all_parameters(&self) -> HashSet<String> {
        let mut all_params = HashSet::new();

        // From forms
        for form in &self.forms {
            for input in &form.inputs {
                // Skip UUID-like parameters (auto-generated form field IDs)
                if !Self::is_uuid_param(&input.name) {
                    all_params.insert(input.name.clone());
                }
            }
        }

        // From URL parameters
        for params in self.parameters.values() {
            for param in params {
                if !Self::is_uuid_param(param) {
                    all_params.insert(param.clone());
                }
            }
        }

        all_params
    }

    /// Check if a parameter name is an auto-generated field ID that shouldn't be tested
    fn is_uuid_param(name: &str) -> bool {
        // Skip empty names
        if name.is_empty() {
            return true;
        }

        // Skip auto-generated field names like checkbox_field_0, radio_field_1, etc.
        if name.starts_with("checkbox_field_") || name.starts_with("radio_field_") {
            return true;
        }

        // Skip generic indexed fields like field_0, input_1, etc.
        if (name.starts_with("field_") || name.starts_with("input_"))
            && name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return true;
        }

        // Check for UUID pattern: f_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if name.contains('-') {
            let dash_count = name.chars().filter(|c| *c == '-').count();
            let hex_chars = name.chars().filter(|c| c.is_ascii_hexdigit()).count();

            // UUID has 4 dashes and 32 hex chars
            if dash_count >= 4 && hex_chars >= 20 {
                return true;
            }

            // Check if it's a prefixed UUID like f_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            if let Some(uuid_part) = name.split('_').last() {
                let parts: Vec<&str> = uuid_part.split('-').collect();
                if parts.len() == 5 {
                    let is_uuid = parts[0].len() == 8
                        && parts[1].len() == 4
                        && parts[2].len() == 4
                        && parts[3].len() == 4
                        && parts[4].len() == 12
                        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
                    if is_uuid {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Deduplicate forms based on their signature
    pub fn deduplicate_forms(&mut self) {
        let mut seen_signatures = HashSet::new();
        let original_count = self.forms.len();

        self.forms.retain(|form| {
            let sig = form.signature();
            seen_signatures.insert(sig)
        });

        let removed = original_count - self.forms.len();
        if removed > 0 {
            info!("Deduplicated {} duplicate forms", removed);
        }
    }
}

/// Robots.txt parsed data including Crawl-delay directive
#[derive(Debug, Clone, Default)]
struct RobotsData {
    /// Whether crawling is allowed for our user-agent
    allowed: bool,
    /// Crawl-delay in seconds (from Crawl-delay directive)
    crawl_delay: Option<Duration>,
    /// Disallowed paths
    disallowed_paths: Vec<String>,
}

pub struct WebCrawler {
    http_client: Arc<HttpClient>,
    max_depth: usize,
    max_pages: usize,
    robots_cache: Arc<tokio::sync::Mutex<HashMap<String, RobotsData>>>, // host -> robots data
    respect_robots: bool,
    /// Adaptive rate limiter for per-target throttling
    rate_limiter: Arc<AdaptiveRateLimiter>,
}

impl WebCrawler {
    pub fn new(http_client: Arc<HttpClient>, max_depth: usize, max_pages: usize) -> Self {
        // Default rate limiter: 50 req/s, backs off on 429/503
        let rate_config = RateLimiterConfig {
            default_rps: 50,
            min_rps: 5,
            max_rps: 200,
            backoff_multiplier: 0.5,
            recovery_multiplier: 1.1,
            adaptive: true,
        };

        Self {
            http_client,
            max_depth,
            max_pages,
            robots_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            respect_robots: true,
            rate_limiter: Arc::new(AdaptiveRateLimiter::new(rate_config)),
        }
    }

    /// Create a new crawler with custom rate limiter config
    pub fn with_rate_limit(
        http_client: Arc<HttpClient>,
        max_depth: usize,
        max_pages: usize,
        rate_config: RateLimiterConfig,
    ) -> Self {
        Self {
            http_client,
            max_depth,
            max_pages,
            robots_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            respect_robots: true,
            rate_limiter: Arc::new(AdaptiveRateLimiter::new(rate_config)),
        }
    }

    /// Create a new crawler that ignores robots.txt
    pub fn new_aggressive(http_client: Arc<HttpClient>, max_depth: usize, max_pages: usize) -> Self {
        let rate_config = RateLimiterConfig {
            default_rps: 100, // Higher for aggressive mode
            min_rps: 10,
            max_rps: 500,
            backoff_multiplier: 0.5,
            recovery_multiplier: 1.2,
            adaptive: true,
        };

        Self {
            http_client,
            max_depth,
            max_pages,
            robots_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            respect_robots: false,
            rate_limiter: Arc::new(AdaptiveRateLimiter::new(rate_config)),
        }
    }

    /// Crawl a website starting from the given URL
    pub async fn crawl(&self, start_url: &str) -> Result<CrawlResults> {
        info!("[Crawler] Starting crawl of {}", start_url);

        let mut results = CrawlResults::new();
        let mut to_visit: Vec<(String, usize)> = vec![(start_url.to_string(), 0)];
        let mut visited: HashSet<String> = HashSet::new();

        // Validate URL for SSRF protection
        let base_url = self.is_safe_url(start_url)?;
        let base_domain = base_url.host_str()
            .context("Failed to get host from URL")?
            .to_string(); // Convert to owned String for Send safety

        // Discover URLs from sitemap.xml
        let sitemap_urls = self.discover_sitemap(&base_url).await;
        for url in sitemap_urls {
            to_visit.push((url, 0));
        }

        while let Some((url, depth)) = to_visit.pop() {
            // Check limits
            if visited.len() >= self.max_pages {
                warn!("[WARNING]  Reached max pages limit ({})", self.max_pages);
                break;
            }

            if depth > self.max_depth {
                continue;
            }

            if visited.contains(&url) {
                continue;
            }

            // SSRF protection - validate each URL
            if let Err(e) = self.is_safe_url(&url) {
                warn!("Skipping unsafe URL {}: {}", url, e);
                continue;
            }

            // Check robots.txt and get crawl-delay
            let crawl_delay = if self.respect_robots {
                if let Ok(parsed_url) = Url::parse(&url) {
                    let robots_data = self.get_robots_data(&parsed_url).await;
                    if !robots_data.allowed {
                        debug!("Skipping {} (blocked by robots.txt)", url);
                        continue;
                    }
                    robots_data.crawl_delay
                } else {
                    None
                }
            } else {
                None
            };

            visited.insert(url.clone());
            results.crawled_urls.insert(url.clone());

            debug!("Crawling: {} (depth: {})", url, depth);

            // Apply rate limiting - wait for slot before making request
            if let Err(e) = self.rate_limiter.wait_for_slot(&url).await {
                warn!("Rate limiter error for {}: {}", url, e);
            }

            // Honor Crawl-delay from robots.txt (takes precedence if specified)
            if let Some(delay) = crawl_delay {
                debug!("Respecting Crawl-delay of {:?} for {}", delay, url);
                tokio::time::sleep(delay).await;
            }

            // Fetch page
            let response = match self.http_client.get(&url).await {
                Ok(resp) => {
                    // Record success for adaptive rate limiting
                    self.rate_limiter.record_success(&url).await;
                    resp
                }
                Err(e) => {
                    // Check if it's a rate limit error (429 or 503)
                    let err_str = e.to_string();
                    if err_str.contains("429") {
                        self.rate_limiter.record_rate_limit(&url, 429).await;
                    } else if err_str.contains("503") {
                        self.rate_limiter.record_rate_limit(&url, 503).await;
                    }
                    warn!("Failed to fetch {}: {}", url, e);
                    continue;
                }
            };

            // Check for rate limiting in response status
            if response.status_code == 429 {
                self.rate_limiter.record_rate_limit(&url, 429).await;
                warn!("Rate limited (429) on {}, backing off", url);
                // Re-add to queue to try again later
                to_visit.insert(0, (url.clone(), depth));
                continue;
            } else if response.status_code == 503 {
                self.rate_limiter.record_rate_limit(&url, 503).await;
                warn!("Service unavailable (503) on {}, backing off", url);
                continue;
            }

            // Check if it's an API endpoint
            if self.is_api_response(&response) {
                results.api_endpoints.insert(url.clone());
            }

            // Parse HTML and extract ALL data synchronously (before any awaits)
            let (forms, links, script_urls, params) = {
                let document = Html::parse_document(&response.body);

                let forms = self.extract_forms(&document, &url);
                let links = self.extract_links(&document, &url, &base_domain);
                let script_urls = self.extract_script_urls(&document, &url);
                let params = self.extract_url_parameters(&document, &url);

                (forms, links, script_urls, params)
            }; // document is dropped here, before any await

            // Now process the extracted data
            results.forms.extend(forms);

            for link in links {
                if !visited.contains(&link) {
                    to_visit.push((link.clone(), depth + 1));
                    results.links.insert(link);
                }
            }

            // Fetch scripts (async operation, after document is dropped)
            for script_url in script_urls {
                // Apply rate limiting to script fetches too
                if let Err(e) = self.rate_limiter.wait_for_slot(&script_url).await {
                    warn!("Rate limiter error for script {}: {}", script_url, e);
                }

                match self.http_client.get(&script_url).await {
                    Ok(response) => {
                        self.rate_limiter.record_success(&script_url).await;
                        results.scripts.push(DiscoveredScript {
                            url: script_url,
                            content: response.body,
                        });
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("429") {
                            self.rate_limiter.record_rate_limit(&script_url, 429).await;
                        }
                        debug!("Failed to fetch script {}: {}", script_url, e);
                    }
                }
            }

            if !params.is_empty() {
                results.parameters.insert(url.clone(), params);
            }
        }

        // Deduplicate forms before returning
        results.deduplicate_forms();

        info!("[SUCCESS] Crawl complete: {} pages, {} forms, {} scripts, {} links",
            results.crawled_urls.len(),
            results.forms.len(),
            results.scripts.len(),
            results.links.len()
        );

        // Detect if likely client-side rendered app (has scripts but no forms/links)
        if results.forms.is_empty() && results.links.is_empty() && !results.scripts.is_empty() {
            results.is_spa = true;
            info!("[WARNING] Site appears to be a client-side rendered app (React/Vue/Angular)");
            info!("[WARNING] Forms and links are rendered by JavaScript - will use headless browser mode");
        }

        Ok(results)
    }

    /// Discover URLs from sitemap.xml
    async fn discover_sitemap(&self, base_url: &Url) -> Vec<String> {
        let sitemap_url = format!("{}://{}/sitemap.xml",
            base_url.scheme(),
            base_url.host_str().unwrap_or("")
        );

        let mut urls = Vec::new();

        if let Ok(resp) = self.http_client.get(&sitemap_url).await {
            // Simple XML parsing - look for <loc> tags
            let body = &resp.body;
            let mut in_loc = false;
            let mut current_url = String::new();

            for line in body.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("<loc>") {
                    in_loc = true;
                    if let Some(url_start) = trimmed.find("<loc>") {
                        if let Some(url_end) = trimmed.find("</loc>") {
                            let url = &trimmed[url_start + 5..url_end];
                            urls.push(url.to_string());
                            in_loc = false;
                        } else {
                            current_url = trimmed[url_start + 5..].to_string();
                        }
                    }
                } else if trimmed.ends_with("</loc>") && in_loc {
                    if let Some(url_end) = trimmed.find("</loc>") {
                        current_url.push_str(trimmed[..url_end].trim());
                        urls.push(current_url.clone());
                        current_url.clear();
                        in_loc = false;
                    }
                } else if in_loc {
                    current_url.push_str(trimmed);
                }
            }
        }

        if !urls.is_empty() {
            info!("Discovered {} URLs from sitemap.xml", urls.len());
        }
        urls
    }

    /// Get robots.txt data including allowed status and Crawl-delay
    async fn get_robots_data(&self, url: &Url) -> RobotsData {
        let host = match url.host_str() {
            Some(h) => h,
            None => return RobotsData { allowed: true, ..Default::default() },
        };

        let mut cache = self.robots_cache.lock().await;

        // Check cache first
        if let Some(cached) = cache.get(host) {
            // Check if this specific path is allowed
            let mut data = cached.clone();
            data.allowed = !cached.disallowed_paths.iter()
                .any(|path| url.path().starts_with(path));
            return data;
        }

        // Fetch robots.txt
        let robots_url = format!("{}://{}/robots.txt", url.scheme(), host);

        let robots_data = match self.http_client.get(&robots_url).await {
            Ok(resp) => {
                self.parse_robots_txt(&resp.body, url)
            }
            Err(_) => {
                // No robots.txt = allow all
                RobotsData { allowed: true, ..Default::default() }
            }
        };

        cache.insert(host.to_string(), robots_data.clone());
        robots_data
    }

    /// Parse robots.txt content and extract rules + Crawl-delay
    fn parse_robots_txt(&self, body: &str, check_url: &Url) -> RobotsData {
        let mut in_our_section = false;
        let mut in_any_section = false;
        let mut crawl_delay: Option<Duration> = None;
        let mut disallowed_paths: Vec<String> = Vec::new();
        let mut allowed = true;

        for line in body.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let lower = trimmed.to_lowercase();

            // Check User-agent directive
            if lower.starts_with("user-agent:") {
                let agent = trimmed[11..].trim().to_lowercase();
                // Our user-agent takes precedence over wildcard
                if agent == "lonkerobot" || agent == "lonkero" {
                    in_our_section = true;
                    in_any_section = true;
                } else if agent == "*" && !in_our_section {
                    // Wildcard applies if no specific section found
                    in_any_section = true;
                } else if in_any_section && !in_our_section {
                    // New user-agent section, reset if we were in wildcard
                    in_any_section = false;
                }
                continue;
            }

            // Only process rules in our section (specific or wildcard)
            if !in_any_section && !in_our_section {
                continue;
            }

            // Parse Crawl-delay directive
            if lower.starts_with("crawl-delay:") {
                let delay_str = trimmed[12..].trim();
                if let Ok(delay_secs) = delay_str.parse::<f64>() {
                    let delay_ms = (delay_secs * 1000.0) as u64;
                    crawl_delay = Some(Duration::from_millis(delay_ms));
                    info!("[robots.txt] Found Crawl-delay: {}s", delay_secs);
                }
                continue;
            }

            // Parse Disallow directive
            if lower.starts_with("disallow:") {
                let path = trimmed[9..].trim();
                if !path.is_empty() {
                    disallowed_paths.push(path.to_string());
                    if check_url.path().starts_with(path) {
                        allowed = false;
                    }
                }
                continue;
            }

            // Parse Allow directive (overrides Disallow)
            if lower.starts_with("allow:") {
                let path = trimmed[6..].trim();
                if !path.is_empty() && check_url.path().starts_with(path) {
                    allowed = true;
                }
            }
        }

        RobotsData {
            allowed,
            crawl_delay,
            disallowed_paths,
        }
    }

    /// Validate URL to prevent SSRF attacks
    fn is_safe_url(&self, url_str: &str) -> Result<Url> {
        let url = Url::parse(url_str)?;

        // Only allow HTTP(S)
        if !matches!(url.scheme(), "http" | "https") {
            return Err(anyhow::anyhow!("Invalid scheme: {}", url.scheme()));
        }

        // Block internal/private IPs
        if let Some(host) = url.host_str() {
            // Block localhost variants
            if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                return Err(anyhow::anyhow!("Cannot crawl localhost"));
            }

            // Block private IP ranges
            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(anyhow::anyhow!("Cannot crawl private IP: {}", ip));
                }
            }
        }

        Ok(url)
    }

    /// Extract forms from HTML
    fn extract_forms(&self, document: &Html, page_url: &str) -> Vec<DiscoveredForm> {
        let mut forms = Vec::new();
        let mut form_input_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input, textarea, select, button").unwrap();

        // First, extract traditional forms
        for form_element in document.select(&form_selector) {
            let action = form_element.value().attr("action")
                .unwrap_or("")
                .to_string();

            let method = form_element.value().attr("method")
                .unwrap_or("GET")
                .to_uppercase();

            let mut inputs_list = Vec::new();

            for input_element in form_element.select(&input_selector) {
                // Get name from 'name' attribute, or fall back to 'id' attribute
                let name = input_element.value().attr("name")
                    .or_else(|| input_element.value().attr("id"));

                if let Some(name) = name {
                    form_input_ids.insert(name.to_string());
                    let input_type = input_element.value().attr("type")
                        .unwrap_or("text")
                        .to_string();

                    let value = input_element.value().attr("value")
                        .map(|v| v.to_string());

                    inputs_list.push(FormInput {
                        name: name.to_string(),
                        input_type,
                        value,
                        options: None,
                        required: false,
                    });
                }
            }

            // Include form even if no named inputs - it's still an attack surface
            let absolute_action = self.resolve_url(page_url, &action);

            forms.push(DiscoveredForm {
                action: absolute_action.clone(),
                method: method.clone(),
                inputs: inputs_list.clone(),
                discovered_at: page_url.to_string(),
            });

            debug!("Found form: {} with {} inputs", action, inputs_list.len());
        }

        // Enhanced: Look for form-like containers in SPAs
        // Many modern frameworks use div/section with class names like "form", "contact", "signup"
        let form_container_selector = Selector::parse(
            "[class*='form'], [class*='contact'], [class*='signup'], [class*='login'], \
             [class*='subscribe'], [class*='newsletter'], [class*='register'], [class*='search'], \
             [class*='feedback'], [class*='comment'], [class*='inquiry'], [class*='booking'], \
             [class*='checkout'], [class*='payment'], [class*='billing'], [class*='shipping'], \
             [data-form], [data-component*='form'], [data-testid*='form'], \
             section[id*='contact'], div[id*='form'], div[id*='contact'], \
             [role='form'], [aria-label*='form'], [aria-label*='contact']"
        ).unwrap_or_else(|_| Selector::parse("form").unwrap());

        for container in document.select(&form_container_selector) {
            // Skip if this is already a form element
            if container.value().name() == "form" {
                continue;
            }

            let mut container_inputs = Vec::new();

            // Look for inputs within this container
            for input_element in container.select(&input_selector) {
                let name = input_element.value().attr("name")
                    .or_else(|| input_element.value().attr("id"))
                    .or_else(|| input_element.value().attr("aria-label"))
                    .or_else(|| input_element.value().attr("placeholder"))
                    .or_else(|| input_element.value().attr("data-testid"));

                if let Some(name) = name {
                    if !form_input_ids.contains(name) {
                        form_input_ids.insert(name.to_string());

                        let tag_name = input_element.value().name();
                        let input_type = input_element.value().attr("type")
                            .unwrap_or(if tag_name == "textarea" { "textarea" } else if tag_name == "select" { "select" } else { "text" })
                            .to_string();

                        let value = input_element.value().attr("value")
                            .map(|v| v.to_string());

                        container_inputs.push(FormInput {
                            name: name.to_string(),
                            input_type,
                            value,
                            options: None,
                            required: false,
                        });
                    }
                }
            }

            // Also look for button/submit elements to identify form endpoints
            let button_selector = Selector::parse("button, [type='submit'], [role='button']").unwrap();
            let mut form_action = page_url.to_string();

            for button in container.select(&button_selector) {
                // Check for data attributes that might indicate submission endpoint
                if let Some(action) = button.value().attr("data-action")
                    .or_else(|| button.value().attr("data-url"))
                    .or_else(|| button.value().attr("data-endpoint"))
                    .or_else(|| button.value().attr("formaction")) {
                    form_action = self.resolve_url(page_url, action);
                    break;
                }
            }

            if !container_inputs.is_empty() {
                let container_class = container.value().attr("class").unwrap_or("");
                debug!("Found form-like container with class '{}' containing {} inputs",
                    container_class, container_inputs.len());

                forms.push(DiscoveredForm {
                    action: form_action,
                    method: "POST".to_string(),
                    inputs: container_inputs,
                    discovered_at: page_url.to_string(),
                });
            }
        }

        // Also look for standalone inputs (React/JS apps without <form> tags)
        // Broad selector: input, textarea, select, and contenteditable elements
        let all_inputs_selector = Selector::parse(
            "input, textarea, select, [contenteditable='true'], [role='textbox'], \
             [role='combobox'], [role='searchbox'], [role='spinbutton']"
        ).unwrap();
        let mut standalone_inputs = Vec::new();
        let mut input_counter = 0;

        for input_element in document.select(&all_inputs_selector) {
            let tag_name = input_element.value().name();
            let input_type = input_element.value().attr("type")
                .unwrap_or(if tag_name == "textarea" { "textarea" } else if tag_name == "select" { "select" } else { "text" })
                .to_lowercase();

            // Skip hidden/submit but keep checkbox/radio (they can be attack vectors)
            if tag_name == "input" && matches!(input_type.as_str(), "hidden" | "submit" | "button" | "image" | "reset") {
                continue;
            }

            // For select elements, extract options and check if it's a language selector
            let options = if tag_name == "select" {
                self.extract_select_options(&input_element)
            } else {
                None
            };

            // Skip language/locale selectors - they're not attack vectors
            if tag_name == "select" && self.is_language_select_options(&options) {
                debug!("Skipping language selector select element");
                continue;
            }

            // Get name from multiple sources (expanded)
            let name = input_element.value().attr("name")
                .or_else(|| input_element.value().attr("id"))
                .or_else(|| input_element.value().attr("aria-label"))
                .or_else(|| input_element.value().attr("aria-labelledby"))
                .or_else(|| input_element.value().attr("placeholder"))
                .or_else(|| input_element.value().attr("data-testid"))
                .or_else(|| input_element.value().attr("data-cy"))
                .or_else(|| input_element.value().attr("data-test"))
                .or_else(|| input_element.value().attr("data-name"))
                .or_else(|| input_element.value().attr("data-field"))
                .or_else(|| input_element.value().attr("data-param"))
                .or_else(|| input_element.value().attr("autocomplete"));

            // Generate name if none found - still track it as an input
            let final_name = match name {
                Some(n) => n.to_string(),
                None => {
                    input_counter += 1;
                    format!("input_{}", input_counter)
                }
            };

            // Skip if already part of a form
            if form_input_ids.contains(&final_name) {
                continue;
            }

            let value = input_element.value().attr("value")
                .map(|v| v.to_string());

            standalone_inputs.push(FormInput {
                name: final_name,
                input_type: input_type.clone(),
                value,
                options,
                required: false,
            });
        }

        // Create a virtual form for standalone inputs (JS-based form submission)
        if !standalone_inputs.is_empty() {
            forms.push(DiscoveredForm {
                action: page_url.to_string(),
                method: "POST".to_string(),
                inputs: standalone_inputs.clone(),
                discovered_at: page_url.to_string(),
            });
            debug!("Found {} standalone inputs (React/JS form)", standalone_inputs.len());
        }

        // Also detect common form parameter names from the page even if no input elements
        // This catches React/Vue components that render inputs dynamically
        let common_form_params = self.detect_form_params_from_html(document);
        if !common_form_params.is_empty() && forms.is_empty() {
            let synthetic_inputs: Vec<FormInput> = common_form_params.into_iter()
                .filter(|p| !form_input_ids.contains(p))
                .map(|name| FormInput {
                    name,
                    input_type: "text".to_string(),
                    value: None,
                    options: None,
                    required: false,
                })
                .collect();

            if !synthetic_inputs.is_empty() {
                debug!("Detected {} potential form params from HTML analysis", synthetic_inputs.len());
                forms.push(DiscoveredForm {
                    action: page_url.to_string(),
                    method: "POST".to_string(),
                    inputs: synthetic_inputs,
                    discovered_at: page_url.to_string(),
                });
            }
        }

        // Extract framework-specific forms (Material-UI, Bootstrap, Tailwind, etc.)
        let framework_forms = self.extract_framework_forms(document, page_url);
        for fw_form in framework_forms {
            // Only add if not duplicate
            let fw_sig = fw_form.signature();
            if !forms.iter().any(|f| f.signature() == fw_sig) {
                forms.push(fw_form);
            }
        }

        forms
    }

    /// Detect potential form parameter names from HTML content
    /// IMPORTANT: This should only detect ACTUAL form fields, not just words on the page
    fn detect_form_params_from_html(&self, document: &Html) -> Vec<String> {
        let mut params = Vec::new();

        // First, check if the page actually has form-like structures
        // Only detect params if we see real form indicators
        let has_form_structure = {
            let form_selector = Selector::parse("form, [role='form'], .form, .contact-form, .signup-form, .login-form").ok();
            let input_selector = Selector::parse("input:not([type='hidden']):not([type='submit']), textarea, select").ok();

            let has_forms = form_selector.map(|s| document.select(&s).next().is_some()).unwrap_or(false);
            let has_inputs = input_selector.map(|s| document.select(&s).next().is_some()).unwrap_or(false);

            has_forms || has_inputs
        };

        // If no form structure exists, don't try to infer params from text
        if !has_form_structure {
            debug!("No form structure detected - skipping text-based param detection");
            return params;
        }

        // Form field name mappings (indicator -> param_name)
        let form_indicators = [
            // Email variations
            ("email", "email"), ("e-mail", "email"), ("sähköposti", "email"),
            ("correo", "email"), ("courriel", "email"),
            // Name variations
            ("nimi", "name"), ("full name", "fullname"),
            ("nombre", "name"), ("nom", "name"),
            // Phone variations
            ("phone", "phone"), ("puhelin", "phone"), ("telephone", "phone"),
            ("telefono", "phone"), ("téléphone", "phone"), ("mobile", "phone"),
            // Message variations
            ("message", "message"), ("viesti", "message"), ("comment", "comment"),
            ("mensaje", "message"), ("feedback", "message"),
            // Subject variations
            ("subject", "subject"), ("aihe", "subject"), ("asunto", "subject"),
            // Company variations
            ("company", "company"), ("yritys", "company"),
            // Auth fields
            ("password", "password"), ("salasana", "password"),
            ("username", "username"), ("käyttäjänimi", "username"),
            // Name parts
            ("first name", "firstname"), ("etunimi", "firstname"),
            ("last name", "lastname"), ("sukunimi", "lastname"),
        ];

        // Look for label elements with for= attribute - these are REAL form fields
        if let Ok(label_selector) = Selector::parse("label[for]") {
            for label in document.select(&label_selector) {
                if let Some(for_attr) = label.value().attr("for") {
                    if !params.contains(&for_attr.to_string()) && for_attr.len() > 1 && for_attr.len() < 50 {
                        params.push(for_attr.to_string());
                    }
                }
            }
        }

        // Look for placeholder attributes - these are REAL form field indicators
        if let Ok(placeholder_selector) = Selector::parse("[placeholder]") {
            for elem in document.select(&placeholder_selector) {
                if let Some(placeholder) = elem.value().attr("placeholder") {
                    let placeholder_lower = placeholder.to_lowercase();
                    for (indicator, param_name) in &form_indicators {
                        if placeholder_lower.contains(indicator) && !params.contains(&param_name.to_string()) {
                            params.push(param_name.to_string());
                        }
                    }
                }
                // Also get name/id from the element itself
                if let Some(name) = elem.value().attr("name").or_else(|| elem.value().attr("id")) {
                    if !params.contains(&name.to_string()) && name.len() > 1 && name.len() < 50 {
                        params.push(name.to_string());
                    }
                }
            }
        }

        // Look for aria-label attributes on input-like elements
        if let Ok(aria_selector) = Selector::parse("input[aria-label], textarea[aria-label], select[aria-label]") {
            for elem in document.select(&aria_selector) {
                if let Some(aria_label) = elem.value().attr("aria-label") {
                    let aria_lower = aria_label.to_lowercase();
                    for (indicator, param_name) in &form_indicators {
                        if aria_lower.contains(indicator) && !params.contains(&param_name.to_string()) {
                            params.push(param_name.to_string());
                        }
                    }
                }
            }
        }

        // Look for data-* attributes that indicate form fields
        if let Ok(data_selector) = Selector::parse("[data-field], [data-name], [data-param], [data-input], [data-form-field], [data-testid]") {
            for elem in document.select(&data_selector) {
                for attr in ["data-field", "data-name", "data-param", "data-input", "data-form-field", "data-testid"] {
                    if let Some(value) = elem.value().attr(attr) {
                        // data-testid often contains field names like "email-input"
                        let clean_value = value.replace("-input", "").replace("-field", "").replace("_input", "").replace("_field", "");
                        if !params.contains(&clean_value) && clean_value.len() > 1 && clean_value.len() < 50 {
                            params.push(clean_value);
                        }
                    }
                }
            }
        }

        // Look specifically inside form containers for label text
        if let Ok(form_label_selector) = Selector::parse("form label, [role='form'] label, .form label") {
            for label in document.select(&form_label_selector) {
                let label_text = label.text().collect::<String>().to_lowercase();
                for (indicator, param_name) in &form_indicators {
                    if label_text.contains(indicator) && !params.contains(&param_name.to_string()) {
                        params.push(param_name.to_string());
                    }
                }
            }
        }

        params
    }

    /// Extract additional forms from framework-specific patterns
    fn extract_framework_forms(&self, document: &Html, page_url: &str) -> Vec<DiscoveredForm> {
        let mut forms = Vec::new();

        // =====================================================================
        // NEXT.JS SPECIFIC DETECTION
        // =====================================================================

        // Extract form fields from Next.js __NEXT_DATA__ script
        if let Ok(next_data_selector) = Selector::parse("script#__NEXT_DATA__") {
            for script in document.select(&next_data_selector) {
                let json_text = script.text().collect::<String>();
                // Look for form-related field names in the JSON
                let form_field_patterns = [
                    "email", "password", "username", "name", "phone", "message",
                    "firstName", "lastName", "company", "address", "city", "subject",
                    "comment", "feedback", "search", "query", "nimi", "viesti", "puhelin",
                ];

                let mut next_inputs = Vec::new();
                for field in form_field_patterns {
                    // Check if field appears as a key in JSON: "email": or "email":
                    let patterns = [
                        format!(r#""{}":\s*"#, field),
                        format!(r#"'{}'\s*:"#, field),
                    ];
                    for pattern in patterns {
                        if let Ok(re) = regex::Regex::new(&pattern) {
                            if re.is_match(&json_text) && !next_inputs.iter().any(|i: &FormInput| i.name == field) {
                                next_inputs.push(FormInput {
                                    name: field.to_string(),
                                    input_type: "text".to_string(),
                                    value: None,
                                    options: None,
                                    required: false,
                                });
                            }
                        }
                    }
                }

                if !next_inputs.is_empty() {
                    debug!("Found {} form fields from __NEXT_DATA__", next_inputs.len());
                    forms.push(DiscoveredForm {
                        action: page_url.to_string(),
                        method: "POST".to_string(),
                        inputs: next_inputs,
                        discovered_at: format!("{} (Next.js SSR data)", page_url),
                    });
                }
            }
        }

        // Look for Next.js RSC payload data (React Server Components)
        if let Ok(rsc_selector) = Selector::parse("script[type='application/rsc'], script[data-rsc]") {
            for script in document.select(&rsc_selector) {
                let rsc_text = script.text().collect::<String>();
                // RSC payloads often contain form field names
                let mut rsc_inputs = Vec::new();
                let field_pattern = r#"(?:name|field|input|param)\s*[=:]\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']"#;
                if let Ok(re) = regex::Regex::new(field_pattern) {
                    for cap in re.captures_iter(&rsc_text) {
                        if let Some(field) = cap.get(1) {
                            let field_name = field.as_str();
                            if !rsc_inputs.iter().any(|i: &FormInput| i.name == field_name) {
                                rsc_inputs.push(FormInput {
                                    name: field_name.to_string(),
                                    input_type: "text".to_string(),
                                    value: None,
                                    options: None,
                                    required: false,
                                });
                            }
                        }
                    }
                }

                if !rsc_inputs.is_empty() {
                    debug!("Found {} form fields from RSC payload", rsc_inputs.len());
                    forms.push(DiscoveredForm {
                        action: page_url.to_string(),
                        method: "POST".to_string(),
                        inputs: rsc_inputs,
                        discovered_at: format!("{} (Next.js RSC)", page_url),
                    });
                }
            }
        }

        // Look for hydration data that might contain form schemas
        if let Ok(hydration_selector) = Selector::parse("script[data-nscript], script[data-next-font]") {
            // These scripts often load after SSR and contain form definitions
            for script in document.select(&hydration_selector) {
                if let Some(src) = script.value().attr("src") {
                    // Mark these for JS mining
                    debug!("Found Next.js hydration script for mining: {}", src);
                }
            }
        }

        // Look for Next.js server action forms
        if let Ok(action_selector) = Selector::parse("[data-action], form[action^='/api'], form[action*='action']") {
            for elem in document.select(&action_selector) {
                let action = elem.value().attr("action")
                    .or_else(|| elem.value().attr("data-action"))
                    .unwrap_or(page_url);

                let mut inputs = Vec::new();
                let input_selector = Selector::parse("input, textarea, select").unwrap();

                for input in elem.select(&input_selector) {
                    if let Some(name) = input.value().attr("name").or_else(|| input.value().attr("id")) {
                        inputs.push(FormInput {
                            name: name.to_string(),
                            input_type: input.value().attr("type").unwrap_or("text").to_string(),
                            value: input.value().attr("value").map(|v| v.to_string()),
                            options: None,
                            required: false,
                        });
                    }
                }

                if !inputs.is_empty() {
                    forms.push(DiscoveredForm {
                        action: self.resolve_url(page_url, action),
                        method: elem.value().attr("method").unwrap_or("POST").to_uppercase(),
                        inputs,
                        discovered_at: page_url.to_string(),
                    });
                }
            }
        }

        // Look for React/Material-UI/Tailwind form patterns
        let mui_patterns = [
            "[class*='MuiTextField'], [class*='MuiInput'], [class*='MuiSelect']",
            "[class*='chakra-input'], [class*='chakra-select'], [class*='chakra-textarea']",
            "[class*='ant-input'], [class*='ant-select'], [class*='ant-form-item']",
            "[class*='bp3-input'], [class*='bp4-input'], [class*='bp5-input']",
        ];

        for pattern in mui_patterns {
            if let Ok(mui_selector) = Selector::parse(pattern) {
                let mut mui_inputs = Vec::new();

                for elem in document.select(&mui_selector) {
                    let name = elem.value().attr("name")
                        .or_else(|| elem.value().attr("id"))
                        .or_else(|| elem.value().attr("aria-label"))
                        .or_else(|| elem.value().attr("data-testid"));

                    if let Some(name) = name {
                        if name.len() > 1 && !mui_inputs.iter().any(|i: &FormInput| i.name == name) {
                            mui_inputs.push(FormInput {
                                name: name.to_string(),
                                input_type: elem.value().attr("type").unwrap_or("text").to_string(),
                                value: elem.value().attr("value").map(|v| v.to_string()),
                                options: None,
                                required: false,
                            });
                        }
                    }
                }

                if !mui_inputs.is_empty() {
                    debug!("Found {} inputs from UI framework pattern", mui_inputs.len());
                    forms.push(DiscoveredForm {
                        action: page_url.to_string(),
                        method: "POST".to_string(),
                        inputs: mui_inputs,
                        discovered_at: page_url.to_string(),
                    });
                }
            }
        }

        // Look for Bootstrap form patterns
        if let Ok(bootstrap_selector) = Selector::parse(".form-group input, .form-group textarea, .form-group select, .form-floating input, .mb-3 input") {
            let mut bootstrap_inputs = Vec::new();

            for elem in document.select(&bootstrap_selector) {
                let name = elem.value().attr("name")
                    .or_else(|| elem.value().attr("id"))
                    .or_else(|| elem.value().attr("placeholder"));

                if let Some(name) = name {
                    if name.len() > 1 && !bootstrap_inputs.iter().any(|i: &FormInput| i.name == name) {
                        bootstrap_inputs.push(FormInput {
                            name: name.to_string(),
                            input_type: elem.value().attr("type").unwrap_or("text").to_string(),
                            value: elem.value().attr("value").map(|v| v.to_string()),
                            options: None,
                            required: false,
                        });
                    }
                }
            }

            if !bootstrap_inputs.is_empty() {
                debug!("Found {} Bootstrap form inputs", bootstrap_inputs.len());
                forms.push(DiscoveredForm {
                    action: page_url.to_string(),
                    method: "POST".to_string(),
                    inputs: bootstrap_inputs,
                    discovered_at: page_url.to_string(),
                });
            }
        }

        // Look for Tailwind form patterns
        if let Ok(tailwind_selector) = Selector::parse("[class*='rounded'][class*='border'] input, [class*='shadow'][class*='rounded'] input, .space-y-4 input, .grid input") {
            let mut tailwind_inputs = Vec::new();

            for elem in document.select(&tailwind_selector) {
                let name = elem.value().attr("name")
                    .or_else(|| elem.value().attr("id"))
                    .or_else(|| elem.value().attr("placeholder"));

                if let Some(name) = name {
                    if name.len() > 1 && !tailwind_inputs.iter().any(|i: &FormInput| i.name == name) {
                        tailwind_inputs.push(FormInput {
                            name: name.to_string(),
                            input_type: elem.value().attr("type").unwrap_or("text").to_string(),
                            value: elem.value().attr("value").map(|v| v.to_string()),
                            options: None,
                            required: false,
                        });
                    }
                }
            }

            if !tailwind_inputs.is_empty() {
                debug!("Found {} Tailwind form inputs", tailwind_inputs.len());
                forms.push(DiscoveredForm {
                    action: page_url.to_string(),
                    method: "POST".to_string(),
                    inputs: tailwind_inputs,
                    discovered_at: page_url.to_string(),
                });
            }
        }

        forms
    }

    /// Extract options from a select element
    fn extract_select_options(&self, select_element: &scraper::ElementRef) -> Option<Vec<String>> {
        let option_selector = Selector::parse("option").ok()?;
        let options: Vec<String> = select_element
            .select(&option_selector)
            .filter_map(|opt| {
                // First try value attribute
                if let Some(val) = opt.value().attr("value") {
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
                // Fall back to text content
                let text = opt.text().collect::<String>();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            })
            .collect();

        if options.is_empty() {
            None
        } else {
            Some(options)
        }
    }

    /// Check if select options look like a language/locale selector
    fn is_language_select_options(&self, options: &Option<Vec<String>>) -> bool {
        if let Some(opts) = options {
            let lang_codes = [
                "en", "fi", "sv", "de", "fr", "es", "it", "nl", "pt", "ja", "zh", "ko", "ru",
                "en-us", "en-gb", "fi-fi", "sv-se", "de-de", "fr-fr", "es-es",
                "english", "finnish", "swedish", "german", "french", "spanish", "italian",
                "suomi", "svenska", "deutsch", "français", "español",
            ];

            // If most options are language codes, it's a language selector
            let lang_matches = opts.iter().filter(|opt| {
                let opt_lower = opt.to_lowercase();
                lang_codes.iter().any(|lc| opt_lower == *lc || opt_lower.starts_with(&format!("{}-", lc)))
            }).count();

            // If at least 2 options match language codes, consider it a language selector
            lang_matches >= 2
        } else {
            false
        }
    }

    /// Extract links from HTML
    fn extract_links(&self, document: &Html, page_url: &str, base_domain: &str) -> Vec<String> {
        let mut links = Vec::new();

        let link_selector = Selector::parse("a[href]").unwrap();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                let absolute_url = self.resolve_url(page_url, href);

                // Only follow same-domain links
                if let Ok(url) = Url::parse(&absolute_url) {
                    if let Some(host) = url.host_str() {
                        if host == base_domain && !href.starts_with('#') && !href.starts_with("javascript:") {
                            links.push(absolute_url);
                        }
                    }
                }
            }
        }

        links
    }

    /// Extract JavaScript file URLs (synchronous)
    fn extract_script_urls(&self, document: &Html, page_url: &str) -> Vec<String> {
        let script_selector = Selector::parse("script[src]").unwrap();

        let script_urls: Vec<String> = document.select(&script_selector)
            .filter_map(|element| element.value().attr("src"))
            .map(|src| self.resolve_url(page_url, src))
            .collect();

        debug!("Found {} script URLs from {}", script_urls.len(), page_url);
        script_urls
    }

    /// Extract URL parameters from links on the page
    fn extract_url_parameters(&self, document: &Html, _page_url: &str) -> HashSet<String> {
        let mut parameters = HashSet::new();

        let link_selector = Selector::parse("a[href]").unwrap();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(url) = Url::parse(&self.resolve_url(_page_url, href)) {
                    for (key, _) in url.query_pairs() {
                        parameters.insert(key.to_string());
                    }
                }
            }
        }

        parameters
    }

    /// Check if response looks like an API
    fn is_api_response(&self, response: &crate::http_client::HttpResponse) -> bool {
        // Check Content-Type
        if let Some(content_type) = response.header("content-type") {
            let ct_lower = content_type.to_lowercase();
            if ct_lower.contains("application/json")
                || ct_lower.contains("application/xml")
                || ct_lower.contains("application/graphql") {
                return true;
            }
        }

        // Check if body is valid JSON
        if serde_json::from_str::<serde_json::Value>(&response.body).is_ok() {
            return true;
        }

        false
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, base: &str, relative: &str) -> String {
        if relative.starts_with("http://") || relative.starts_with("https://") {
            return relative.to_string();
        }

        if let Ok(base_url) = Url::parse(base) {
            if let Ok(resolved) = base_url.join(relative) {
                return resolved.to_string();
            }
        }

        relative.to_string()
    }
}

/// Check if IP address is private/internal
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
            || ipv4.is_loopback()
            || ipv4.is_link_local()
            || ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 // 169.254.0.0/16
            || ipv4.octets()[0] == 10 // 10.0.0.0/8
            || (ipv4.octets()[0] == 172 && (16..=31).contains(&ipv4.octets()[1])) // 172.16.0.0/12
            || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168) // 192.168.0.0/16
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unspecified()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_url() {
        let crawler = WebCrawler::new(
            Arc::new(HttpClient::new(30, 3).unwrap()),
            2,
            100
        );

        assert_eq!(
            crawler.resolve_url("https://example.com/page", "/api/test"),
            "https://example.com/api/test"
        );

        assert_eq!(
            crawler.resolve_url("https://example.com/page", "https://other.com/test"),
            "https://other.com/test"
        );
    }

    #[test]
    fn test_crawl_results_merge() {
        let mut results1 = CrawlResults::new();
        results1.links.insert("https://example.com/1".to_string());

        let mut results2 = CrawlResults::new();
        results2.links.insert("https://example.com/2".to_string());

        results1.merge(results2);

        assert_eq!(results1.links.len(), 2);
    }

    #[test]
    fn test_form_signature() {
        let form1 = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None, options: None, required: false },
                FormInput { name: "password".to_string(), input_type: "password".to_string(), value: None, options: None, required: false },
            ],
            discovered_at: "/login".to_string(),
        };

        let form2 = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                FormInput { name: "password".to_string(), input_type: "password".to_string(), value: None, options: None, required: false },
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None, options: None, required: false },
            ],
            discovered_at: "/login".to_string(),
        };

        // Same inputs in different order should have same signature
        assert_eq!(form1.signature(), form2.signature());
    }

    #[test]
    fn test_deduplicate_forms() {
        let mut results = CrawlResults::new();

        let form = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None, options: None, required: false },
            ],
            discovered_at: "/page1".to_string(),
        };

        results.forms.push(form.clone());
        results.forms.push(form.clone());
        results.forms.push(form);

        assert_eq!(results.forms.len(), 3);
        results.deduplicate_forms();
        assert_eq!(results.forms.len(), 1);
    }

    #[test]
    fn test_is_private_ip() {
        use std::net::Ipv4Addr;

        // Private IPs
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));

        // Public IPs
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
