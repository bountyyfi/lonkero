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
}

pub struct WebCrawler {
    http_client: Arc<HttpClient>,
    max_depth: usize,
    max_pages: usize,
}

impl WebCrawler {
    pub fn new(http_client: Arc<HttpClient>, max_depth: usize, max_pages: usize) -> Self {
        Self {
            http_client,
            max_depth,
            max_pages,
        }
    }

    /// Crawl a website starting from the given URL
    pub async fn crawl(&self, start_url: &str) -> Result<CrawlResults> {
        info!("[Crawler] Starting crawl of {}", start_url);

        let mut results = CrawlResults::new();
        let mut to_visit: Vec<(String, usize)> = vec![(start_url.to_string(), 0)];
        let mut visited: HashSet<String> = HashSet::new();

        let base_url = Url::parse(start_url)
            .context("Failed to parse start URL")?;
        let base_domain = base_url.host_str()
            .context("Failed to get host from URL")?
            .to_string(); // Convert to owned String for Send safety

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

        info!("[SUCCESS] Crawl complete: {} pages, {} forms, {} scripts, {} links",
            results.crawled_urls.len(),
            results.forms.len(),
            results.scripts.len(),
            results.links.len()
        );

        Ok(results)
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

        // Also look for standalone inputs (React/JS apps without <form> tags)
        // Use broad selector, then filter by type
        let all_inputs_selector = Selector::parse("input, textarea").unwrap();
        let mut standalone_inputs = Vec::new();

        for input_element in document.select(&all_inputs_selector) {
            let input_type = input_element.value().attr("type")
                .unwrap_or("text")
                .to_lowercase();

            // Skip non-data inputs
            if matches!(input_type.as_str(), "hidden" | "submit" | "button" | "checkbox" | "radio" | "file" | "image" | "reset") {
                continue;
            }

            // Get name from multiple sources: name, id, aria-label, placeholder
            let name = input_element.value().attr("name")
                .or_else(|| input_element.value().attr("id"))
                .or_else(|| input_element.value().attr("aria-label"))
                .or_else(|| input_element.value().attr("placeholder"));

            if let Some(name) = name {
                // Skip if already part of a form
                if form_input_ids.contains(name) {
                    continue;
                }

                let value = input_element.value().attr("value")
                    .map(|v| v.to_string());

                standalone_inputs.push(FormInput {
                    name: name.to_string(),
                    input_type: input_type.clone(),
                    value,
                });
            }
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
}
