// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Framework & Technology Detection
 * Identifies frameworks, CDNs, cloud services, and technologies
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use anyhow::Result;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectedTechnology {
    pub name: String,
    pub category: TechCategory,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TechCategory {
    Framework,
    CDN,
    CloudProvider,
    Server,
    Language,
    CMS,
    Analytics,
    JavaScript,
    CSS,
    WAF,
    LoadBalancer,
    Database,
    ApiGateway,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

pub struct FrameworkDetector {
    http_client: Arc<HttpClient>,
    patterns: DetectionPatterns,
}

struct DetectionPatterns {
    header_patterns: HashMap<String, Vec<TechSignature>>,
    body_patterns: Vec<TechSignature>,
    url_patterns: Vec<TechSignature>,
    meta_patterns: Vec<TechSignature>,
    cookie_patterns: Vec<TechSignature>,
}

#[derive(Clone)]
struct TechSignature {
    name: String,
    category: TechCategory,
    pattern: String,
    version_regex: Option<String>,
    confidence: Confidence,
}

impl FrameworkDetector {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            patterns: DetectionPatterns::default(),
        }
    }

    pub async fn detect(&self, url: &str) -> Result<HashSet<DetectedTechnology>> {
        info!("Detecting technologies for: {}", url);

        let mut detected = HashSet::new();
        let mut was_blocked = false;

        detected.extend(self.detect_from_url(url));

        match self.http_client.get(url).await {
            Ok(response) => {
                detected.extend(self.detect_from_blocked_response(&response));
                detected.extend(self.detect_from_headers(&response));

                if response.status_code == 200 {
                    detected.extend(self.detect_from_html(&response));
                    detected.extend(self.detect_from_meta_tags(&response));
                    detected.extend(self.detect_from_scripts(&response));
                    detected.extend(self.detect_from_cookies(&response));
                    detected.extend(self.detect_from_favicon(url).await);
                } else if response.status_code == 403 || response.status_code == 503 {
                    // WAF/Bot protection detected - need headless browser
                    was_blocked = true;
                    info!("[WAF-Detected] Got {} response, will try headless browser for tech detection", response.status_code);
                }
            }
            Err(e) => {
                debug!("Could not fetch {} for technology detection: {}", url, e);
            }
        }

        // If blocked by WAF, try headless browser to get real page content
        if was_blocked {
            detected.extend(self.detect_with_headless(url).await);
        }

        info!("[SUCCESS] Detected {} technologies", detected.len());
        for tech in &detected {
            debug!("  - {} ({:?}) - Confidence: {:?}", tech.name, tech.category, tech.confidence);
        }

        Ok(detected)
    }

    /// Detect technologies using headless browser (for WAF-blocked sites)
    async fn detect_with_headless(&self, url: &str) -> HashSet<DetectedTechnology> {
        use headless_chrome::{Browser, LaunchOptionsBuilder};
        use std::time::Duration;

        let mut detected = HashSet::new();

        info!("[Headless-Tech] Using headless browser to bypass WAF for tech detection");

        let launch_options = LaunchOptionsBuilder::default()
            .headless(true)
            .sandbox(false)
            .idle_browser_timeout(Duration::from_secs(30))
            .build()
            .ok();

        let browser = match launch_options {
            Some(opts) => Browser::new(opts).ok(),
            None => None,
        };

        if let Some(browser) = browser {
            if let Ok(tab) = browser.new_tab() {
                if tab.navigate_to(url).is_ok() {
                    // Wait for page to load
                    std::thread::sleep(Duration::from_secs(3));

                    // Get rendered HTML
                    if let Ok(html) = tab.get_content() {
                        let html_lower = html.to_lowercase();

                        // Detect frameworks from rendered HTML
                        let html_patterns = vec![
                            ("__next", "Next.js", TechCategory::Framework, Confidence::High),
                            ("_next/", "Next.js", TechCategory::Framework, Confidence::High),
                            ("__next_data__", "Next.js", TechCategory::Framework, Confidence::High),
                            ("data-next-head", "Next.js", TechCategory::Framework, Confidence::High),
                            ("__nuxt", "Nuxt.js", TechCategory::Framework, Confidence::High),
                            ("_nuxt/", "Nuxt.js", TechCategory::Framework, Confidence::High),
                            ("data-reactroot", "React", TechCategory::JavaScript, Confidence::High),
                            ("data-react-helmet", "React", TechCategory::JavaScript, Confidence::High),
                            ("data-v-", "Vue.js", TechCategory::JavaScript, Confidence::High),
                            ("__vue__", "Vue.js", TechCategory::JavaScript, Confidence::High),
                            ("ng-version", "Angular", TechCategory::JavaScript, Confidence::High),
                            ("_nghost", "Angular", TechCategory::JavaScript, Confidence::High),
                            ("wp-content", "WordPress", TechCategory::CMS, Confidence::High),
                            ("wp-includes", "WordPress", TechCategory::CMS, Confidence::High),
                            ("shopify", "Shopify", TechCategory::CMS, Confidence::High),
                            ("cdn.shopify.com", "Shopify", TechCategory::CMS, Confidence::High),
                        ];

                        for (pattern, name, category, confidence) in html_patterns {
                            if html_lower.contains(pattern) {
                                info!("[Headless-Tech] Detected {} via headless browser", name);
                                detected.insert(DetectedTechnology {
                                    name: name.to_string(),
                                    category,
                                    version: None,
                                    confidence,
                                    evidence: vec![format!("Headless browser found: {}", pattern)],
                                });
                            }
                        }
                    }
                }
            }
        }

        detected
    }

    fn detect_from_url(&self, url: &str) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let url_lower = url.to_lowercase();

        let url_patterns = vec![
            ("pages.dev", "Cloudflare Pages", TechCategory::CloudProvider),
            ("vercel.app", "Vercel", TechCategory::CloudProvider),
            ("netlify.app", "Netlify", TechCategory::CloudProvider),
            ("netlify.com", "Netlify", TechCategory::CloudProvider),
            ("herokuapp.com", "Heroku", TechCategory::CloudProvider),
            ("azurewebsites.net", "Azure App Service", TechCategory::CloudProvider),
            ("azurestaticapps.net", "Azure Static Web Apps", TechCategory::CloudProvider),
            ("s3.amazonaws.com", "Amazon S3", TechCategory::CloudProvider),
            ("s3-website", "Amazon S3", TechCategory::CloudProvider),
            ("firebaseapp.com", "Firebase Hosting", TechCategory::CloudProvider),
            ("web.app", "Firebase Hosting", TechCategory::CloudProvider),
            ("github.io", "GitHub Pages", TechCategory::CloudProvider),
            ("gitlab.io", "GitLab Pages", TechCategory::CloudProvider),
            ("surge.sh", "Surge.sh", TechCategory::CloudProvider),
            ("render.com", "Render", TechCategory::CloudProvider),
            ("fly.dev", "Fly.io", TechCategory::CloudProvider),
            ("railway.app", "Railway", TechCategory::CloudProvider),
        ];

        for (pattern, name, category) in url_patterns {
            if url_lower.contains(pattern) {
                detected.insert(DetectedTechnology {
                    name: name.to_string(),
                    category,
                    version: None,
                    confidence: Confidence::High,
                    evidence: vec![format!("URL contains: {}", pattern)],
                });
            }
        }

        detected
    }

    fn detect_from_blocked_response(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        if response.status_code == 403 || response.status_code == 503 {
            let body_lower = response.body.to_lowercase();

            let waf_signatures = vec![
                ("cloudflare", "Cloudflare WAF", TechCategory::WAF),
                ("access denied", "Cloudflare", TechCategory::CDN),
                ("cf-ray", "Cloudflare", TechCategory::CDN),
                ("akamai", "Akamai WAF", TechCategory::WAF),
                ("incapsula", "Imperva Incapsula", TechCategory::WAF),
                ("wordfence", "Wordfence", TechCategory::WAF),
                ("sucuri", "Sucuri WAF", TechCategory::WAF),
                ("mod_security", "ModSecurity", TechCategory::WAF),
                ("aws waf", "AWS WAF", TechCategory::WAF),
            ];

            for (pattern, name, category) in waf_signatures {
                if body_lower.contains(pattern) {
                    detected.insert(DetectedTechnology {
                        name: name.to_string(),
                        category,
                        version: None,
                        confidence: Confidence::High,
                        evidence: vec![format!("Block page contains: {}", pattern)],
                    });
                }
            }

            if response.header("cf-ray").is_some() {
                detected.insert(DetectedTechnology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::CDN,
                    version: None,
                    confidence: Confidence::High,
                    evidence: vec!["CF-Ray header present on 403".to_string()],
                });
            }
        }

        detected
    }

    fn detect_from_headers(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        if let Some(server) = response.header("server") {
            let server_lower = server.to_lowercase();
            let evidence = vec![format!("Server: {}", server)];

            let server_patterns = vec![
                ("nginx", "Nginx", TechCategory::Server, Some("nginx/")),
                ("apache", "Apache", TechCategory::Server, Some("apache/")),
                ("cloudflare", "Cloudflare", TechCategory::CDN, None),
                ("microsoft-iis", "Microsoft IIS", TechCategory::Server, Some("microsoft-iis/")),
                ("litespeed", "LiteSpeed", TechCategory::Server, Some("litespeed/")),
                ("caddy", "Caddy", TechCategory::Server, None),
                ("lighttpd", "Lighttpd", TechCategory::Server, Some("lighttpd/")),
                ("openresty", "OpenResty", TechCategory::Server, None),
                ("tomcat", "Apache Tomcat", TechCategory::Server, Some("tomcat/")),
                ("coyote", "Apache Tomcat (Coyote)", TechCategory::Server, None),
            ];

            for (pattern, name, category, version_prefix) in server_patterns {
                if server_lower.contains(pattern) {
                    let version = version_prefix.and_then(|prefix| {
                        self.extract_version(&server_lower, prefix)
                    });
                    detected.insert(DetectedTechnology {
                        name: name.to_string(),
                        category,
                        version,
                        confidence: Confidence::High,
                        evidence: evidence.clone(),
                    });
                }
            }
        }

        let header_detections = vec![
            // CDNs
            ("cf-ray", "Cloudflare", TechCategory::CDN, Confidence::High),
            ("cf-cache-status", "Cloudflare", TechCategory::CDN, Confidence::High),
            ("x-amz-cf-id", "Amazon CloudFront", TechCategory::CDN, Confidence::High),
            ("x-amz-cf-pop", "Amazon CloudFront", TechCategory::CDN, Confidence::High),
            ("x-akamai-transformed", "Akamai", TechCategory::CDN, Confidence::High),
            ("x-fastly-request-id", "Fastly", TechCategory::CDN, Confidence::High),
            ("x-cdn", "Generic CDN", TechCategory::CDN, Confidence::Medium),
            ("x-azure-ref", "Azure CDN", TechCategory::CDN, Confidence::High),
            ("x-bunny-cache", "Bunny CDN", TechCategory::CDN, Confidence::High),
            ("bunny-cache-status", "Bunny CDN", TechCategory::CDN, Confidence::High),
            ("cdn-pullzone", "Bunny CDN", TechCategory::CDN, Confidence::High),
            ("x-keycdn-cache-status", "KeyCDN", TechCategory::CDN, Confidence::High),
            ("x-sp-cache-status", "StackPath", TechCategory::CDN, Confidence::High),
            ("x-sp-server", "StackPath", TechCategory::CDN, Confidence::High),
            // Cloud providers
            ("x-vercel-id", "Vercel", TechCategory::CloudProvider, Confidence::High),
            ("x-vercel-cache", "Vercel", TechCategory::CloudProvider, Confidence::High),
            ("x-nf-request-id", "Netlify", TechCategory::CloudProvider, Confidence::High),
            ("x-github-request-id", "GitHub", TechCategory::CloudProvider, Confidence::High),
            ("x-heroku-queue-wait-time", "Heroku", TechCategory::CloudProvider, Confidence::High),
            ("fly-request-id", "Fly.io", TechCategory::CloudProvider, Confidence::High),
            ("x-render-origin-server", "Render", TechCategory::CloudProvider, Confidence::High),
            // API Gateways
            ("x-kong-request-id", "Kong", TechCategory::ApiGateway, Confidence::High),
            ("x-kong-upstream-latency", "Kong", TechCategory::ApiGateway, Confidence::High),
            ("x-kong-proxy-latency", "Kong", TechCategory::ApiGateway, Confidence::High),
            ("kong-request-id", "Kong", TechCategory::ApiGateway, Confidence::High),
            ("x-tyk-request-id", "Tyk", TechCategory::ApiGateway, Confidence::High),
            ("x-ratelimit-remaining", "Tyk", TechCategory::ApiGateway, Confidence::Medium),
            ("x-amzn-requestid", "AWS API Gateway", TechCategory::ApiGateway, Confidence::High),
            ("x-amz-apigw-id", "AWS API Gateway", TechCategory::ApiGateway, Confidence::High),
            ("x-amzn-trace-id", "AWS API Gateway", TechCategory::ApiGateway, Confidence::Medium),
            ("x-ms-request-id", "Azure API Management", TechCategory::ApiGateway, Confidence::High),
            ("ocp-apim-subscription-key", "Azure API Management", TechCategory::ApiGateway, Confidence::High),
            ("apim-request-id", "Azure API Management", TechCategory::ApiGateway, Confidence::High),
            ("x-goog-api-client", "Google Cloud Endpoints", TechCategory::ApiGateway, Confidence::High),
            ("x-apigee-request-id", "Apigee", TechCategory::ApiGateway, Confidence::High),
        ];

        for (header, name, category, confidence) in header_detections {
            if let Some(value) = response.header(header) {
                detected.insert(DetectedTechnology {
                    name: name.to_string(),
                    category,
                    version: None,
                    confidence,
                    evidence: vec![format!("{}: {}", header, value)],
                });
            }
        }

        if let Some(powered_by) = response.header("x-powered-by") {
            let pb_lower = powered_by.to_lowercase();
            let evidence = vec![format!("X-Powered-By: {}", powered_by)];

            let powered_by_patterns = vec![
                ("php", "PHP", TechCategory::Language, Some("php/")),
                ("express", "Express", TechCategory::Framework, None),
                ("asp.net", "ASP.NET", TechCategory::Framework, None),
                ("next.js", "Next.js", TechCategory::Framework, None),
                ("nuxt", "Nuxt.js", TechCategory::Framework, None),
                ("django", "Django", TechCategory::Framework, None),
                ("rails", "Ruby on Rails", TechCategory::Framework, None),
                ("laravel", "Laravel", TechCategory::Framework, None),
                ("symfony", "Symfony", TechCategory::Framework, None),
                // Python frameworks
                ("flask", "Flask", TechCategory::Framework, None),
                ("fastapi", "FastAPI", TechCategory::Framework, None),
                ("tornado", "Tornado", TechCategory::Framework, None),
                ("starlette", "Starlette", TechCategory::Framework, None),
                ("uvicorn", "Uvicorn", TechCategory::Server, None),
                ("gunicorn", "Gunicorn", TechCategory::Server, None),
                // Go frameworks
                ("gin", "Gin", TechCategory::Framework, None),
                ("echo", "Echo", TechCategory::Framework, None),
                ("fiber", "Fiber", TechCategory::Framework, None),
                ("chi", "Chi", TechCategory::Framework, None),
                ("gorilla", "Gorilla", TechCategory::Framework, None),
                // Rust frameworks
                ("actix", "Actix Web", TechCategory::Framework, None),
                ("rocket", "Rocket", TechCategory::Framework, None),
                ("axum", "Axum", TechCategory::Framework, None),
                ("warp", "Warp", TechCategory::Framework, None),
                ("hyper", "Hyper", TechCategory::Server, None),
            ];

            for (pattern, name, category, version_prefix) in powered_by_patterns {
                if pb_lower.contains(pattern) {
                    let version = version_prefix.and_then(|prefix| {
                        self.extract_version(&pb_lower, prefix)
                    });
                    detected.insert(DetectedTechnology {
                        name: name.to_string(),
                        category,
                        version,
                        confidence: Confidence::High,
                        evidence: evidence.clone(),
                    });
                }
            }
        }

        if let Some(waf_header) = response.header("x-sucuri-id") {
            detected.insert(DetectedTechnology {
                name: "Sucuri WAF".to_string(),
                category: TechCategory::WAF,
                version: None,
                confidence: Confidence::High,
                evidence: vec![format!("X-Sucuri-ID: {}", waf_header)],
            });
        }

        if let Some(waf_header) = response.header("x-sucuri-cache") {
            detected.insert(DetectedTechnology {
                name: "Sucuri WAF".to_string(),
                category: TechCategory::WAF,
                version: None,
                confidence: Confidence::High,
                evidence: vec![format!("X-Sucuri-Cache: {}", waf_header)],
            });
        }

        detected
    }

    fn detect_from_meta_tags(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let document = Html::parse_document(&response.body);

        if let Ok(generator_selector) = Selector::parse("meta[name='generator']") {
            for element in document.select(&generator_selector) {
                if let Some(content) = element.value().attr("content") {
                    let content_lower = content.to_lowercase();
                    let evidence = vec![format!("Generator meta tag: {}", content)];

                    let generators = vec![
                        ("wordpress", "WordPress", TechCategory::CMS),
                        ("drupal", "Drupal", TechCategory::CMS),
                        ("joomla", "Joomla", TechCategory::CMS),
                        ("wix", "Wix", TechCategory::CMS),
                        ("squarespace", "Squarespace", TechCategory::CMS),
                        ("shopify", "Shopify", TechCategory::CMS),
                        ("ghost", "Ghost", TechCategory::CMS),
                        ("hugo", "Hugo", TechCategory::Framework),
                        ("jekyll", "Jekyll", TechCategory::Framework),
                        ("gatsby", "Gatsby", TechCategory::Framework),
                        ("next.js", "Next.js", TechCategory::Framework),
                        ("nuxt", "Nuxt.js", TechCategory::Framework),
                        ("docusaurus", "Docusaurus", TechCategory::Framework),
                    ];

                    for (pattern, name, category) in generators {
                        if content_lower.contains(pattern) {
                            let version = self.extract_version_advanced(&content_lower);
                            detected.insert(DetectedTechnology {
                                name: name.to_string(),
                                category,
                                version,
                                confidence: Confidence::High,
                                evidence: evidence.clone(),
                            });
                        }
                    }
                }
            }
        }

        if let Ok(next_data_selector) = Selector::parse("script[id='__NEXT_DATA__']") {
            if document.select(&next_data_selector).next().is_some() {
                detected.insert(DetectedTechnology {
                    name: "Next.js".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                    evidence: vec!["__NEXT_DATA__ script found".to_string()],
                });
            }
        }

        if let Ok(nuxt_selector) = Selector::parse("script[id='__NUXT_DATA__']") {
            if document.select(&nuxt_selector).next().is_some() {
                detected.insert(DetectedTechnology {
                    name: "Nuxt.js".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                    evidence: vec!["__NUXT_DATA__ script found".to_string()],
                });
            }
        }

        detected
    }

    fn detect_from_html(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let body_lower = response.body.to_lowercase();

        let html_patterns = vec![
            ("__next", "Next.js", TechCategory::Framework, Confidence::High),
            ("_next/", "Next.js", TechCategory::Framework, Confidence::High),
            ("__next_data__", "Next.js", TechCategory::Framework, Confidence::High),
            ("__nuxt", "Nuxt.js", TechCategory::Framework, Confidence::High),
            ("_nuxt/", "Nuxt.js", TechCategory::Framework, Confidence::High),
            ("__remix", "Remix", TechCategory::Framework, Confidence::High),
            ("__svelte", "SvelteKit", TechCategory::Framework, Confidence::High),
            ("__astro", "Astro", TechCategory::Framework, Confidence::High),
            // Modern JS Frameworks
            ("__qwik", "Qwik", TechCategory::Framework, Confidence::High),
            ("q:container", "Qwik", TechCategory::Framework, Confidence::High),
            ("qwikloader", "Qwik", TechCategory::Framework, Confidence::High),
            ("@builder.io/qwik", "Qwik", TechCategory::Framework, Confidence::High),
            ("_solid", "Solid.js", TechCategory::Framework, Confidence::High),
            ("solid-js", "Solid.js", TechCategory::Framework, Confidence::High),
            ("data-hk", "Solid.js", TechCategory::Framework, Confidence::Medium),
            ("__preact", "Preact", TechCategory::Framework, Confidence::High),
            ("preact", "Preact", TechCategory::Framework, Confidence::Medium),
            ("__fresh", "Fresh", TechCategory::Framework, Confidence::High),
            ("_frsh", "Fresh", TechCategory::Framework, Confidence::High),
            ("__hono", "Hono", TechCategory::Framework, Confidence::High),
            ("hono", "Hono", TechCategory::Framework, Confidence::Low),
            ("data-reactroot", "React", TechCategory::JavaScript, Confidence::High),
            ("data-react-helmet", "React", TechCategory::JavaScript, Confidence::High),
            ("__react", "React", TechCategory::JavaScript, Confidence::Medium),
            ("data-v-", "Vue.js", TechCategory::JavaScript, Confidence::High),
            ("__vue__", "Vue.js", TechCategory::JavaScript, Confidence::High),
            ("ng-version", "Angular", TechCategory::JavaScript, Confidence::High),
            ("_nghost", "Angular", TechCategory::JavaScript, Confidence::High),
            ("ng-app", "Angular", TechCategory::JavaScript, Confidence::High),
            ("wp-content", "WordPress", TechCategory::CMS, Confidence::High),
            ("wp-includes", "WordPress", TechCategory::CMS, Confidence::High),
            ("/sites/default/files", "Drupal", TechCategory::CMS, Confidence::High),
            ("drupal.settings", "Drupal", TechCategory::CMS, Confidence::High),
            ("joomla", "Joomla", TechCategory::CMS, Confidence::Medium),
            ("com_content", "Joomla", TechCategory::CMS, Confidence::High),
            ("shopify", "Shopify", TechCategory::CMS, Confidence::High),
            ("cdn.shopify.com", "Shopify", TechCategory::CMS, Confidence::High),
            ("wix.com", "Wix", TechCategory::CMS, Confidence::High),
            ("squarespace", "Squarespace", TechCategory::CMS, Confidence::High),
            ("bootstrap", "Bootstrap", TechCategory::CSS, Confidence::Medium),
            ("tailwind", "Tailwind CSS", TechCategory::CSS, Confidence::Medium),
            ("tw-", "Tailwind CSS", TechCategory::CSS, Confidence::Low),
            ("material-ui", "Material-UI", TechCategory::CSS, Confidence::Medium),
            ("chakra-ui", "Chakra UI", TechCategory::CSS, Confidence::Medium),
            ("jquery.min.js", "jQuery", TechCategory::JavaScript, Confidence::High),
            ("jquery.js", "jQuery", TechCategory::JavaScript, Confidence::High),
            ("jquery-", "jQuery", TechCategory::JavaScript, Confidence::Medium),
            ("jquery/", "jQuery", TechCategory::JavaScript, Confidence::Medium),
            ("google-analytics", "Google Analytics", TechCategory::Analytics, Confidence::High),
            ("gtag", "Google Analytics 4", TechCategory::Analytics, Confidence::High),
            ("ga.js", "Google Analytics", TechCategory::Analytics, Confidence::High),
            ("googletagmanager", "Google Tag Manager", TechCategory::Analytics, Confidence::High),
            ("hotjar", "Hotjar", TechCategory::Analytics, Confidence::High),
            ("segment.com", "Segment", TechCategory::Analytics, Confidence::High),
            ("mixpanel", "Mixpanel", TechCategory::Analytics, Confidence::High),
            ("amplitude", "Amplitude", TechCategory::Analytics, Confidence::High),
            ("intercom", "Intercom", TechCategory::Other, Confidence::High),
            ("zendesk", "Zendesk", TechCategory::Other, Confidence::High),
            ("stripe", "Stripe", TechCategory::Other, Confidence::Medium),
            ("paypal", "PayPal", TechCategory::Other, Confidence::Medium),
        ];

        for (pattern, name, category, confidence) in html_patterns {
            if body_lower.contains(pattern) {
                detected.insert(DetectedTechnology {
                    name: name.to_string(),
                    category,
                    version: None,
                    confidence,
                    evidence: vec![format!("Body contains: {}", pattern)],
                });
            }
        }

        detected
    }

    fn detect_from_scripts(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let body = &response.body;

        let script_patterns = vec![
            ("webpack", "Webpack", TechCategory::JavaScript),
            ("__webpack", "Webpack", TechCategory::JavaScript),
            ("vite", "Vite", TechCategory::JavaScript),
            ("/@vite/", "Vite", TechCategory::JavaScript),
            ("parcel", "Parcel", TechCategory::JavaScript),
            ("rollup", "Rollup", TechCategory::JavaScript),
            ("turbopack", "Turbopack", TechCategory::JavaScript),
            ("esbuild", "esbuild", TechCategory::JavaScript),
        ];

        for (pattern, name, category) in script_patterns {
            if body.contains(pattern) {
                detected.insert(DetectedTechnology {
                    name: name.to_string(),
                    category,
                    version: None,
                    confidence: Confidence::Medium,
                    evidence: vec![format!("Script contains: {}", pattern)],
                });
            }
        }

        detected
    }

    fn detect_from_cookies(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        if let Some(cookies) = response.header("set-cookie") {
            let cookies_lower = cookies.to_lowercase();

            let cookie_patterns = vec![
                ("laravel_session", "Laravel", TechCategory::Framework, Confidence::High),
                ("phpsessid", "PHP", TechCategory::Language, Confidence::Medium),
                ("jsessionid", "Java", TechCategory::Language, Confidence::High),
                ("asp.net_sessionid", "ASP.NET", TechCategory::Framework, Confidence::High),
                ("__requestverificationtoken", "ASP.NET", TechCategory::Framework, Confidence::High),
                ("csrftoken", "Django", TechCategory::Framework, Confidence::Medium),
                ("sessionid", "Django", TechCategory::Framework, Confidence::Low),
                ("_session", "Ruby on Rails", TechCategory::Framework, Confidence::Medium),
                ("wordpress_", "WordPress", TechCategory::CMS, Confidence::High),
                ("wp-settings", "WordPress", TechCategory::CMS, Confidence::High),
                ("__cfduid", "Cloudflare", TechCategory::CDN, Confidence::High),
                ("cf_clearance", "Cloudflare", TechCategory::CDN, Confidence::High),
            ];

            for (pattern, name, category, confidence) in cookie_patterns {
                if cookies_lower.contains(pattern) {
                    detected.insert(DetectedTechnology {
                        name: name.to_string(),
                        category,
                        version: None,
                        confidence,
                        evidence: vec![format!("Cookie: {}", pattern)],
                    });
                }
            }
        }

        detected
    }

    async fn detect_from_favicon(&self, base_url: &str) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        let favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));

        match self.http_client.get(&favicon_url).await {
            Ok(response) if response.status_code == 200 => {
                let hash = self.calculate_favicon_hash(&response.body);

                let known_hashes = vec![
                    (116323821_i64, "WordPress", TechCategory::CMS),
                    (-697231548_i64, "Drupal", TechCategory::CMS),
                    (81586312_i64, "Joomla", TechCategory::CMS),
                ];

                for (known_hash, name, category) in known_hashes {
                    if hash == known_hash {
                        detected.insert(DetectedTechnology {
                            name: name.to_string(),
                            category,
                            version: None,
                            confidence: Confidence::High,
                            evidence: vec![format!("Favicon hash: {}", hash)],
                        });
                    }
                }
            }
            _ => {}
        }

        detected
    }

    fn calculate_favicon_hash(&self, data: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish() as i64
    }

    fn extract_version(&self, text: &str, prefix: &str) -> Option<String> {
        if let Some(start) = text.find(prefix) {
            let version_start = start + prefix.len();
            let version_str = &text[version_start..];

            let version = version_str
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                .collect::<String>();

            if !version.is_empty() && version.chars().any(|c| c.is_ascii_digit()) {
                return Some(version.trim_end_matches(['.', '-']).to_string());
            }
        }

        None
    }

    fn extract_version_advanced(&self, text: &str) -> Option<String> {
        let version_regex = Regex::new(r"(\d+\.[\d.]+\d+|\d+\.\d+)").ok()?;

        if let Some(cap) = version_regex.captures(text) {
            return Some(cap[1].to_string());
        }

        None
    }
}

impl Default for DetectionPatterns {
    fn default() -> Self {
        Self {
            header_patterns: HashMap::new(),
            body_patterns: Vec::new(),
            url_patterns: Vec::new(),
            meta_patterns: Vec::new(),
            cookie_patterns: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        let detector = FrameworkDetector::new(Arc::new(HttpClient::new(30, 3).unwrap()));

        assert_eq!(
            detector.extract_version("nginx/1.18.0", "nginx/"),
            Some("1.18.0".to_string())
        );

        assert_eq!(
            detector.extract_version("apache/2.4.41 (ubuntu)", "apache/"),
            Some("2.4.41".to_string())
        );

        assert_eq!(
            detector.extract_version("PHP/7.4.3", "php/"),
            Some("7.4.3".to_string())
        );
    }

    #[test]
    fn test_extract_version_advanced() {
        let detector = FrameworkDetector::new(Arc::new(HttpClient::new(30, 3).unwrap()));

        assert_eq!(
            detector.extract_version_advanced("WordPress 6.4.2"),
            Some("6.4.2".to_string())
        );

        assert_eq!(
            detector.extract_version_advanced("Next.js v14.0.3"),
            Some("14.0.3".to_string())
        );
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn test_detect_from_url() {
        let detector = FrameworkDetector::new(Arc::new(HttpClient::new(30, 3).unwrap()));

        let detected = detector.detect_from_url("https://example.vercel.app");
        assert!(detected.iter().any(|t| t.name == "Vercel"));

        let detected = detector.detect_from_url("https://example.pages.dev");
        assert!(detected.iter().any(|t| t.name == "Cloudflare Pages"));

        let detected = detector.detect_from_url("https://bucket.s3.amazonaws.com");
        assert!(detected.iter().any(|t| t.name == "Amazon S3"));
    }
}
