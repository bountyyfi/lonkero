// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Technology Detection Module
 * Wappalyzer-style technology fingerprinting for web applications
 * Fast, accurate detection of frameworks, CMS, servers, and more
 * © 2025 Bountyy Oy
 */

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

/// Technology category types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TechCategory {
    Framework,
    CMS,
    Server,
    Language,
    CDN,
    Analytics,
    Security,
    Database,
    Cloud,
    JavaScript,
    CSS,
    WebServer,
    CacheServer,
    MessageQueue,
    PaymentProcessor,
    Advertising,
    Marketing,
    DevTools,
    Container,
    Monitoring,
    Other,
}

impl TechCategory {
    pub fn as_str(&self) -> &str {
        match self {
            TechCategory::Framework => "framework",
            TechCategory::CMS => "cms",
            TechCategory::Server => "server",
            TechCategory::Language => "language",
            TechCategory::CDN => "cdn",
            TechCategory::Analytics => "analytics",
            TechCategory::Security => "security",
            TechCategory::Database => "database",
            TechCategory::Cloud => "cloud",
            TechCategory::JavaScript => "javascript",
            TechCategory::CSS => "css",
            TechCategory::WebServer => "web-server",
            TechCategory::CacheServer => "cache-server",
            TechCategory::MessageQueue => "message-queue",
            TechCategory::PaymentProcessor => "payment",
            TechCategory::Advertising => "advertising",
            TechCategory::Marketing => "marketing",
            TechCategory::DevTools => "dev-tools",
            TechCategory::Container => "container",
            TechCategory::Monitoring => "monitoring",
            TechCategory::Other => "other",
        }
    }
}

/// Detected technology with confidence and evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTechnology {
    pub name: String,
    pub category: TechCategory,
    pub version: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

/// Technology detection pattern
#[derive(Debug, Clone)]
struct TechPattern {
    name: String,
    category: TechCategory,
    patterns: Vec<Pattern>,
    implies: Vec<String>,
    excludes: Vec<String>,
}

/// Pattern types for detection
#[derive(Debug, Clone)]
enum Pattern {
    Header { name: String, regex: String },
    HTML { regex: String },
    Script { regex: String },
    Cookie { name: String },
    Meta { name: String, regex: String },
    DOM { selector: String, attribute: Option<String>, regex: Option<String> },
    URL { regex: String },
    Text { regex: String },
}

/// Technology detector
pub struct TechDetector {
    patterns: Vec<TechPattern>,
    compiled_regexes: RefCell<HashMap<String, Regex>>,
}

impl TechDetector {
    /// Create new technology detector
    pub fn new() -> Self {
        let mut detector = Self {
            patterns: Vec::new(),
            compiled_regexes: RefCell::new(HashMap::new()),
        };

        detector.load_default_patterns();
        detector
    }

    /// Load default technology detection patterns
    fn load_default_patterns(&mut self) {
        // Web Frameworks
        self.add_pattern(TechPattern {
            name: "React".to_string(),
            category: TechCategory::Framework,
            patterns: vec![
                Pattern::HTML { regex: r"react(?:\.production\.min)?\.js".to_string() },
                Pattern::HTML { regex: r"data-reactroot".to_string() },
                Pattern::HTML { regex: r"_react".to_string() },
            ],
            implies: vec!["JavaScript".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Vue.js".to_string(),
            category: TechCategory::Framework,
            patterns: vec![
                Pattern::HTML { regex: r"vue(?:\.runtime)?(?:\.min)?\.js".to_string() },
                Pattern::HTML { regex: r"data-v-[0-9a-f]{8}".to_string() },
                Pattern::HTML { regex: r"<[^>]+v-(?:bind|if|for|on|show|model)".to_string() },
            ],
            implies: vec!["JavaScript".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Angular".to_string(),
            category: TechCategory::Framework,
            patterns: vec![
                Pattern::HTML { regex: r"ng-(?:app|controller|model|view)".to_string() },
                Pattern::Script { regex: r"angular(?:\.min)?\.js".to_string() },
                Pattern::HTML { regex: r"<[^>]+\[ng-".to_string() },
            ],
            implies: vec!["JavaScript".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Next.js".to_string(),
            category: TechCategory::Framework,
            patterns: vec![
                Pattern::HTML { regex: r"__NEXT_DATA__".to_string() },
                Pattern::HTML { regex: r"/_next/static/".to_string() },
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"Next\.js".to_string() },
            ],
            implies: vec!["React".to_string(), "Node.js".to_string()],
            excludes: vec![],
        });

        // CMS Systems
        self.add_pattern(TechPattern {
            name: "WordPress".to_string(),
            category: TechCategory::CMS,
            patterns: vec![
                Pattern::HTML { regex: r"wp-content".to_string() },
                Pattern::HTML { regex: r"wp-includes".to_string() },
                Pattern::Meta { name: "generator".to_string(), regex: r"WordPress\s*([\d.]+)?".to_string() },
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"WordPress".to_string() },
            ],
            implies: vec!["PHP".to_string(), "MySQL".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Drupal".to_string(),
            category: TechCategory::CMS,
            patterns: vec![
                Pattern::HTML { regex: r"drupal\.js".to_string() },
                Pattern::Header { name: "x-generator".to_string(), regex: r"Drupal\s*([\d.]+)?".to_string() },
                Pattern::HTML { regex: r"sites/(?:default|all)/(?:themes|modules)".to_string() },
                Pattern::Cookie { name: "SESS".to_string() },
            ],
            implies: vec!["PHP".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Joomla".to_string(),
            category: TechCategory::CMS,
            patterns: vec![
                Pattern::HTML { regex: r"/media/system/js/".to_string() },
                Pattern::Meta { name: "generator".to_string(), regex: r"Joomla!\s*([\d.]+)?".to_string() },
                Pattern::HTML { regex: r"com_content".to_string() },
            ],
            implies: vec!["PHP".to_string()],
            excludes: vec![],
        });

        // Web Servers
        self.add_pattern(TechPattern {
            name: "Nginx".to_string(),
            category: TechCategory::WebServer,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"nginx(?:/([\d.]+))?".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Apache".to_string(),
            category: TechCategory::WebServer,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Apache(?:/([\d.]+))?".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Microsoft-IIS".to_string(),
            category: TechCategory::WebServer,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Microsoft-IIS(?:/([\d.]+))?".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // CDN Providers
        self.add_pattern(TechPattern {
            name: "Cloudflare".to_string(),
            category: TechCategory::CDN,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"cloudflare".to_string() },
                Pattern::Header { name: "cf-ray".to_string(), regex: r".+".to_string() },
                Pattern::Cookie { name: "__cfduid".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Akamai".to_string(),
            category: TechCategory::CDN,
            patterns: vec![
                Pattern::Header { name: "x-akamai-transformed".to_string(), regex: r".+".to_string() },
                Pattern::Header { name: "x-akamai-staging".to_string(), regex: r".+".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Fastly".to_string(),
            category: TechCategory::CDN,
            patterns: vec![
                Pattern::Header { name: "x-served-by".to_string(), regex: r"cache-".to_string() },
                Pattern::Header { name: "fastly-io-info".to_string(), regex: r".+".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Analytics
        self.add_pattern(TechPattern {
            name: "Google Analytics".to_string(),
            category: TechCategory::Analytics,
            patterns: vec![
                Pattern::Script { regex: r"google-analytics\.com/(?:ga|urchin|analytics)\.js".to_string() },
                Pattern::Script { regex: r"googletagmanager\.com/gtag/js".to_string() },
                Pattern::HTML { regex: r#"ga\(['"]create['"]\)"#.to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Mixpanel".to_string(),
            category: TechCategory::Analytics,
            patterns: vec![
                Pattern::Script { regex: r"mixpanel\.com/libs/mixpanel".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Hotjar".to_string(),
            category: TechCategory::Analytics,
            patterns: vec![
                Pattern::Script { regex: r"static\.hotjar\.com".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Security Technologies
        self.add_pattern(TechPattern {
            name: "reCAPTCHA".to_string(),
            category: TechCategory::Security,
            patterns: vec![
                Pattern::Script { regex: r"google\.com/recaptcha".to_string() },
                Pattern::HTML { regex: r"g-recaptcha".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Imperva".to_string(),
            category: TechCategory::Security,
            patterns: vec![
                Pattern::Cookie { name: "incap_ses_".to_string() },
                Pattern::Cookie { name: "visid_incap_".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Programming Languages
        self.add_pattern(TechPattern {
            name: "PHP".to_string(),
            category: TechCategory::Language,
            patterns: vec![
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"PHP(?:/([\d.]+))?".to_string() },
                Pattern::Cookie { name: "PHPSESSID".to_string() },
                Pattern::URL { regex: r"\.php(?:\?|$)".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Node.js".to_string(),
            category: TechCategory::Language,
            patterns: vec![
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"(?:Node\.js|Express)".to_string() },
            ],
            implies: vec!["JavaScript".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Python".to_string(),
            category: TechCategory::Language,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Python(?:/([\d.]+))?".to_string() },
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"Django|Flask".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Ruby".to_string(),
            category: TechCategory::Language,
            patterns: vec![
                Pattern::Header { name: "x-powered-by".to_string(), regex: r"(?:Phusion Passenger|mod_rails|mod_rack)".to_string() },
                Pattern::Cookie { name: "_rails_session".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Cloud Platforms
        self.add_pattern(TechPattern {
            name: "AWS".to_string(),
            category: TechCategory::Cloud,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"AmazonS3".to_string() },
                Pattern::Header { name: "x-amz-".to_string(), regex: r".+".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Google Cloud".to_string(),
            category: TechCategory::Cloud,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Google Frontend".to_string() },
                Pattern::Header { name: "x-goog-".to_string(), regex: r".+".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Microsoft Azure".to_string(),
            category: TechCategory::Cloud,
            patterns: vec![
                Pattern::Header { name: "x-ms-".to_string(), regex: r".+".to_string() },
                Pattern::Header { name: "x-azure-ref".to_string(), regex: r".+".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // JavaScript Libraries
        self.add_pattern(TechPattern {
            name: "jQuery".to_string(),
            category: TechCategory::JavaScript,
            patterns: vec![
                Pattern::Script { regex: r"jquery(?:[-.]min)?\.js".to_string() },
                Pattern::HTML { regex: r#"jQuery\.fn\.jquery\s*=\s*["']([^"']+)"#.to_string() },
            ],
            implies: vec!["JavaScript".to_string()],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Bootstrap".to_string(),
            category: TechCategory::CSS,
            patterns: vec![
                Pattern::HTML { regex: r#"bootstrap(?:\.min)?\.css"#.to_string() },
                Pattern::HTML { regex: r#"bootstrap(?:\.min)?\.js"#.to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Payment Processors
        self.add_pattern(TechPattern {
            name: "Stripe".to_string(),
            category: TechCategory::PaymentProcessor,
            patterns: vec![
                Pattern::Script { regex: r#"js\.stripe\.com"#.to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "PayPal".to_string(),
            category: TechCategory::PaymentProcessor,
            patterns: vec![
                Pattern::Script { regex: r#"paypal\.com"#.to_string() },
                Pattern::HTML { regex: r#"paypal-button"#.to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        // Container/Orchestration
        self.add_pattern(TechPattern {
            name: "Docker".to_string(),
            category: TechCategory::Container,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Docker".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });

        self.add_pattern(TechPattern {
            name: "Kubernetes".to_string(),
            category: TechCategory::Container,
            patterns: vec![
                Pattern::Header { name: "server".to_string(), regex: r"Kubernetes".to_string() },
            ],
            implies: vec![],
            excludes: vec![],
        });
    }

    /// Add a technology pattern
    fn add_pattern(&mut self, pattern: TechPattern) {
        self.patterns.push(pattern);
    }

    /// Detect technologies from HTTP response data
    pub fn detect(
        &self,
        headers: &HashMap<String, String>,
        html: Option<&str>,
        scripts: Option<&[String]>,
        cookies: Option<&HashMap<String, String>>,
        url: Option<&str>,
    ) -> Vec<DetectedTechnology> {
        let mut detected: HashMap<String, DetectedTechnology> = HashMap::new();

        // Normalize headers to lowercase
        let normalized_headers: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Check each pattern
        for pattern in &self.patterns {
            let mut evidence = Vec::new();
            let mut matches = 0;
            let total_patterns = pattern.patterns.len();

            for pat in &pattern.patterns {
                match pat {
                    Pattern::Header { name, regex } => {
                        if let Some(value) = normalized_headers.get(&name.to_lowercase()) {
                            if self.test_regex(regex, value) {
                                evidence.push(format!("Header {}: {}", name, value));
                                matches += 1;
                            }
                        }
                    }
                    Pattern::HTML { regex } => {
                        if let Some(html_content) = html {
                            if self.test_regex(regex, html_content) {
                                evidence.push(format!("HTML pattern: {}", regex));
                                matches += 1;
                            }
                        }
                    }
                    Pattern::Script { regex } => {
                        if let Some(script_srcs) = scripts {
                            for src in script_srcs {
                                if self.test_regex(regex, src) {
                                    evidence.push(format!("Script: {}", src));
                                    matches += 1;
                                    break;
                                }
                            }
                        }
                    }
                    Pattern::Cookie { name } => {
                        if let Some(cookie_map) = cookies {
                            if cookie_map.contains_key(name) {
                                evidence.push(format!("Cookie: {}", name));
                                matches += 1;
                            }
                        }
                    }
                    Pattern::Meta { name, regex } => {
                        if let Some(html_content) = html {
                            let meta_pattern = format!(r##"<meta[^>]+name=["']{}["'][^>]+content=["']([^"']+)["']"##, name);
                            if let Some(content) = self.extract_regex(&meta_pattern, html_content) {
                                if self.test_regex(regex, &content) {
                                    evidence.push(format!("Meta {}: {}", name, content));
                                    matches += 1;
                                }
                            }
                        }
                    }
                    Pattern::URL { regex } => {
                        if let Some(url_str) = url {
                            if self.test_regex(regex, url_str) {
                                evidence.push(format!("URL pattern: {}", regex));
                                matches += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Calculate confidence based on matches
            if matches > 0 {
                let confidence = (matches as f32 / total_patterns as f32).min(1.0);

                // Extract version if possible
                let version = self.extract_version(&evidence);

                detected.insert(
                    pattern.name.clone(),
                    DetectedTechnology {
                        name: pattern.name.clone(),
                        category: pattern.category.clone(),
                        version,
                        confidence,
                        evidence,
                    },
                );
            }
        }

        // Process implications
        let mut implied: HashMap<String, DetectedTechnology> = HashMap::new();
        for pattern in &self.patterns {
            if detected.contains_key(&pattern.name) {
                for imply in &pattern.implies {
                    if !detected.contains_key(imply) && !implied.contains_key(imply) {
                        implied.insert(
                            imply.clone(),
                            DetectedTechnology {
                                name: imply.clone(),
                                category: TechCategory::Other,
                                version: None,
                                confidence: 0.5, // Lower confidence for implied technologies
                                evidence: vec![format!("Implied by {}", pattern.name)],
                            },
                        );
                    }
                }
            }
        }

        // Merge implied technologies
        for (name, tech) in implied {
            detected.insert(name, tech);
        }

        detected.into_values().collect()
    }

    /// Test a regex pattern against text
    fn test_regex(&self, pattern: &str, text: &str) -> bool {
        let regex = self.get_or_compile_regex(pattern);
        regex.is_match(text)
    }

    /// Extract first match from regex
    fn extract_regex(&self, pattern: &str, text: &str) -> Option<String> {
        let regex = self.get_or_compile_regex(pattern);
        regex.captures(text).and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
    }

    /// Get or compile regex (with caching)
    fn get_or_compile_regex(&self, pattern: &str) -> Regex {
        let mut cache = self.compiled_regexes.borrow_mut();
        if let Some(regex) = cache.get(pattern) {
            regex.clone()
        } else {
            let regex = Regex::new(pattern).unwrap_or_else(|_| Regex::new("(?!)").unwrap());
            cache.insert(pattern.to_string(), regex.clone());
            regex
        }
    }

    /// Extract version from evidence
    fn extract_version(&self, evidence: &[String]) -> Option<String> {
        let version_regex = Regex::new(r"(?:v|version|Ver\.?)\s*([\d.]+)").unwrap();

        for ev in evidence {
            if let Some(cap) = version_regex.captures(ev) {
                if let Some(version) = cap.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }

        None
    }
}

impl Default for TechDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx() {
        let mut detector = TechDetector::new();
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());

        let results = detector.detect(&headers, None, None, None, None);

        assert!(results.iter().any(|t| t.name == "Nginx"));
    }

    #[test]
    fn test_detect_wordpress() {
        let mut detector = TechDetector::new();
        let headers = HashMap::new();
        let html = r#"<html><head><meta name="generator" content="WordPress 5.8" /></head><body><link href="wp-content/themes/"></body></html>"#;

        let results = detector.detect(&headers, Some(html), None, None, None);

        assert!(results.iter().any(|t| t.name == "WordPress"));
    }

    #[test]
    fn test_detect_react() {
        let mut detector = TechDetector::new();
        let headers = HashMap::new();
        let html = r#"<div data-reactroot></div>"#;

        let results = detector.detect(&headers, Some(html), None, None, None);

        assert!(results.iter().any(|t| t.name == "React"));
    }

    #[test]
    fn test_detect_cloudflare() {
        let mut detector = TechDetector::new();
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "cloudflare".to_string());
        headers.insert("cf-ray".to_string(), "12345-SJC".to_string());

        let results = detector.detect(&headers, None, None, None, None);

        assert!(results.iter().any(|t| t.name == "Cloudflare"));
    }
}
