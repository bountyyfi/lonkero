// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Web Crawler Module
 * Discovers attack surfaces: forms, inputs, APIs, links
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use anyhow::{Context, Result};
use scraper::{Html, Selector};
use std::collections::{HashSet, HashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
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
        }
    }

    /// Merge another CrawlResults into this one
    pub fn merge(&mut self, other: CrawlResults) {
        self.forms.extend(other.forms);
        self.links.extend(other.links);
        self.scripts.extend(other.scripts);
        self.crawled_urls.extend(other.crawled_urls);
        self.api_endpoints.extend(other.api_endpoints);

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
                all_params.insert(input.name.clone());
            }
        }

        // From URL parameters
        for params in self.parameters.values() {
            all_params.extend(params.clone());
        }

        all_params
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

pub struct WebCrawler {
    http_client: Arc<HttpClient>,
    max_depth: usize,
    max_pages: usize,
    robots_cache: Arc<tokio::sync::Mutex<HashMap<String, bool>>>, // host -> allowed
    respect_robots: bool,
}

impl WebCrawler {
    pub fn new(http_client: Arc<HttpClient>, max_depth: usize, max_pages: usize) -> Self {
        Self {
            http_client,
            max_depth,
            max_pages,
            robots_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            respect_robots: true,
        }
    }

    /// Create a new crawler that ignores robots.txt
    pub fn new_aggressive(http_client: Arc<HttpClient>, max_depth: usize, max_pages: usize) -> Self {
        Self {
            http_client,
            max_depth,
            max_pages,
            robots_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            respect_robots: false,
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

            // Check robots.txt
            if self.respect_robots {
                if let Ok(parsed_url) = Url::parse(&url) {
                    if !self.is_allowed_by_robots(&parsed_url).await {
                        debug!("Skipping {} (blocked by robots.txt)", url);
                        continue;
                    }
                }
            }

            visited.insert(url.clone());
            results.crawled_urls.insert(url.clone());

            debug!("Crawling: {} (depth: {})", url, depth);

            // Fetch page
            let response = match self.http_client.get(&url).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to fetch {}: {}", url, e);
                    continue;
                }
            };

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
                if let Ok(response) = self.http_client.get(&script_url).await {
                    results.scripts.push(DiscoveredScript {
                        url: script_url,
                        content: response.body,
                    });
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

        // Warn if likely client-side rendered app (has scripts but no forms/links)
        if results.forms.is_empty() && results.links.is_empty() && !results.scripts.is_empty() {
            info!("[WARNING] Site appears to be a client-side rendered app (React/Vue/Angular)");
            info!("[WARNING] Forms and links are rendered by JavaScript - consider using headless browser mode");
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

    /// Check if URL is allowed by robots.txt
    async fn is_allowed_by_robots(&self, url: &Url) -> bool {
        let host = match url.host_str() {
            Some(h) => h,
            None => return true, // No host = allow
        };

        let mut cache = self.robots_cache.lock().await;

        // Check cache first
        if let Some(&allowed) = cache.get(host) {
            return allowed;
        }

        // Fetch robots.txt
        let robots_url = format!("{}://{}/robots.txt", url.scheme(), host);

        let allowed = match self.http_client.get(&robots_url).await {
            Ok(resp) => {
                // Simple robots.txt parsing - look for Disallow directives for our user-agent
                let body = &resp.body;
                let mut in_our_section = false;
                let mut allowed = true;

                for line in body.lines() {
                    let trimmed = line.trim();

                    // Check User-agent directive
                    if trimmed.to_lowercase().starts_with("user-agent:") {
                        let agent = trimmed[11..].trim().to_lowercase();
                        in_our_section = agent == "*" || agent == "lonkerobot" || agent == "lonkero";
                    }

                    // Check Disallow directive in our section
                    if in_our_section && trimmed.to_lowercase().starts_with("disallow:") {
                        let path = trimmed[9..].trim();
                        if !path.is_empty() && url.path().starts_with(path) {
                            allowed = false;
                            break;
                        }
                    }
                }

                allowed
            }
            Err(_) => {
                // No robots.txt = allow all
                true
            }
        };

        cache.insert(host.to_string(), allowed);
        allowed
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
    fn detect_form_params_from_html(&self, document: &Html) -> Vec<String> {
        let mut params = Vec::new();
        let html_text = document.root_element().text().collect::<String>();

        // Common form field labels that indicate form presence (multi-language)
        let form_indicators = [
            // Email variations
            ("email", "email"), ("e-mail", "email"), ("sähköposti", "email"),
            ("correo", "email"), ("courriel", "email"), ("邮箱", "email"),
            // Name variations
            ("name", "name"), ("nimi", "name"), ("full name", "fullname"),
            ("nombre", "name"), ("nom", "name"), ("名前", "name"),
            // Phone variations
            ("phone", "phone"), ("puhelin", "phone"), ("telephone", "phone"),
            ("telefono", "phone"), ("téléphone", "phone"), ("mobile", "phone"),
            ("cell", "phone"), ("contact number", "phone"),
            // Message/comment variations
            ("message", "message"), ("viesti", "message"), ("comment", "comment"),
            ("mensaje", "message"), ("commentaire", "comment"), ("feedback", "message"),
            ("inquiry", "message"), ("question", "message"),
            // Subject variations
            ("subject", "subject"), ("aihe", "subject"), ("asunto", "subject"),
            ("sujet", "subject"), ("topic", "subject"),
            // Company/org variations
            ("company", "company"), ("yritys", "company"), ("organization", "organization"),
            ("empresa", "company"), ("société", "company"), ("business", "company"),
            // Address variations
            ("address", "address"), ("osoite", "address"), ("direccion", "address"),
            ("adresse", "address"), ("street", "address"), ("住所", "address"),
            // City/location variations
            ("city", "city"), ("kaupunki", "city"), ("ciudad", "city"),
            ("ville", "city"), ("town", "city"), ("location", "city"),
            // Country variations
            ("country", "country"), ("maa", "country"), ("pais", "country"),
            ("pays", "country"), ("国", "country"),
            // Auth fields
            ("password", "password"), ("salasana", "password"), ("contraseña", "password"),
            ("mot de passe", "password"), ("confirm password", "password_confirm"),
            ("username", "username"), ("käyttäjänimi", "username"), ("usuario", "username"),
            ("login", "username"), ("user", "username"),
            // Name parts
            ("first name", "firstname"), ("etunimi", "firstname"), ("prenom", "firstname"),
            ("last name", "lastname"), ("sukunimi", "lastname"), ("apellido", "lastname"),
            ("family name", "lastname"), ("surname", "lastname"),
            // Search
            ("search", "search"), ("haku", "search"), ("buscar", "search"),
            ("query", "query"), ("keyword", "search"),
            // Other common fields
            ("zip", "zip"), ("postal", "postalcode"), ("postinumero", "postalcode"),
            ("website", "website"), ("url", "url"), ("www", "website"),
            ("date", "date"), ("birthday", "birthday"), ("syntymäpäivä", "birthday"),
            ("age", "age"), ("gender", "gender"), ("sex", "gender"),
            ("newsletter", "newsletter"), ("subscribe", "subscribe"),
            ("agree", "terms"), ("accept", "terms"), ("consent", "consent"),
            ("budget", "budget"), ("price", "price"), ("amount", "amount"),
            ("quantity", "quantity"), ("number", "number"),
            ("file", "file"), ("upload", "file"), ("attachment", "file"),
            ("description", "description"), ("kuvaus", "description"),
            ("title", "title"), ("otsikko", "title"),
            ("reason", "reason"), ("syy", "reason"),
            ("interest", "interest"), ("service", "service"),
            ("product", "product"), ("order", "order"),
        ];

        let html_lower = html_text.to_lowercase();

        for (indicator, param_name) in form_indicators {
            if html_lower.contains(indicator) {
                if !params.contains(&param_name.to_string()) {
                    params.push(param_name.to_string());
                }
            }
        }

        // Look for label elements
        if let Ok(label_selector) = Selector::parse("label") {
            for label in document.select(&label_selector) {
                if let Some(for_attr) = label.value().attr("for") {
                    if !params.contains(&for_attr.to_string()) && for_attr.len() > 1 {
                        params.push(for_attr.to_string());
                    }
                }
                // Also get label text content
                let label_text = label.text().collect::<String>().to_lowercase();
                for (indicator, param_name) in &form_indicators {
                    if label_text.contains(indicator) && !params.contains(&param_name.to_string()) {
                        params.push(param_name.to_string());
                    }
                }
            }
        }

        // Look for data-* attributes that might indicate form fields
        if let Ok(data_selector) = Selector::parse("[data-field], [data-name], [data-param], [data-input], [data-form-field]") {
            for elem in document.select(&data_selector) {
                for attr in ["data-field", "data-name", "data-param", "data-input", "data-form-field"] {
                    if let Some(value) = elem.value().attr(attr) {
                        if !params.contains(&value.to_string()) && value.len() > 1 {
                            params.push(value.to_string());
                        }
                    }
                }
            }
        }

        // Look for elements with common form-related class names
        if let Ok(class_selector) = Selector::parse("[class*='input'], [class*='field'], [class*='form-control'], [class*='text-field']") {
            for elem in document.select(&class_selector) {
                // Try to get field name from various attributes
                for attr in ["name", "id", "data-name", "aria-label", "placeholder"] {
                    if let Some(value) = elem.value().attr(attr) {
                        if !params.contains(&value.to_string()) && value.len() > 1 && value.len() < 50 {
                            params.push(value.to_string());
                        }
                    }
                }
            }
        }

        params
    }

    /// Extract additional forms from framework-specific patterns
    fn extract_framework_forms(&self, document: &Html, page_url: &str) -> Vec<DiscoveredForm> {
        let mut forms = Vec::new();

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
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None },
                FormInput { name: "password".to_string(), input_type: "password".to_string(), value: None },
            ],
            discovered_at: "/login".to_string(),
        };

        let form2 = DiscoveredForm {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                FormInput { name: "password".to_string(), input_type: "password".to_string(), value: None },
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None },
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
                FormInput { name: "email".to_string(), input_type: "text".to_string(), value: None },
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
