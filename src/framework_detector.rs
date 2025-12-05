// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Framework & Technology Detection
 * Identifies frameworks, CDNs, cloud services, and technologies
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectedTechnology {
    pub name: String,
    pub category: TechCategory,
    pub version: Option<String>,
    pub confidence: Confidence,
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
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

pub struct FrameworkDetector {
    http_client: Arc<HttpClient>,
}

impl FrameworkDetector {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Detect all technologies used by a website
    pub async fn detect(&self, url: &str) -> Result<HashSet<DetectedTechnology>> {
        info!("Detecting technologies for: {}", url);

        let mut detected = HashSet::new();

        // URL-based detection (works even if blocked or unreachable)
        detected.extend(self.detect_from_url(url));

        // Try to fetch the main page - but don't fail if unreachable
        match self.http_client.get(url).await {
            Ok(response) => {
                // Detect from blocked responses (403, 503, etc)
                detected.extend(self.detect_from_blocked_response(&response));

                // Header-based detection
                detected.extend(self.detect_from_headers(&response));

                // HTML-based detection (only if we got content)
                if response.status_code == 200 {
                    detected.extend(self.detect_from_html(&response));
                    detected.extend(self.detect_from_scripts(&response));
                    detected.extend(self.detect_from_cookies(&response));
                }
            }
            Err(e) => {
                debug!("Could not fetch {} for technology detection: {}", url, e);
                // Continue with URL-based detections only
            }
        }

        info!("[SUCCESS] Detected {} technologies", detected.len());
        for tech in &detected {
            debug!("  - {} ({:?})", tech.name, tech.category);
        }

        Ok(detected)
    }

    /// Detect from URL patterns (works even when site blocks us)
    fn detect_from_url(&self, url: &str) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let url_lower = url.to_lowercase();

        // Cloudflare Pages
        if url_lower.contains("pages.dev") {
            detected.insert(DetectedTechnology {
                name: "Cloudflare Pages".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Vercel
        if url_lower.contains("vercel.app") {
            detected.insert(DetectedTechnology {
                name: "Vercel".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Netlify
        if url_lower.contains("netlify.app") || url_lower.contains("netlify.com") {
            detected.insert(DetectedTechnology {
                name: "Netlify".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // AWS S3
        if url_lower.contains("s3.amazonaws.com") || url_lower.contains(".s3-website") {
            detected.insert(DetectedTechnology {
                name: "Amazon S3".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        detected
    }

    /// Detect from blocked/error responses
    fn detect_from_blocked_response(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        // Cloudflare block detection
        if response.status_code == 403 || response.status_code == 503 {
            let body_lower = response.body.to_lowercase();

            if body_lower.contains("access denied")
                || body_lower.contains("cloudflare")
                || body_lower.contains("cf-ray") {
                detected.insert(DetectedTechnology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::CDN,
                    version: None,
                    confidence: Confidence::High,
                });
            }

            // Check for Cloudflare Ray ID in headers even on 403
            if response.header("cf-ray").is_some() {
                detected.insert(DetectedTechnology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::CDN,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        detected
    }

    /// Detect technologies from HTTP headers
    fn detect_from_headers(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        // Server header
        if let Some(server) = response.header("server") {
            let server_lower = server.to_lowercase();

            if server_lower.contains("nginx") {
                detected.insert(DetectedTechnology {
                    name: "Nginx".to_string(),
                    category: TechCategory::Server,
                    version: self.extract_version(&server_lower, "nginx/"),
                    confidence: Confidence::High,
                });
            }

            if server_lower.contains("apache") {
                detected.insert(DetectedTechnology {
                    name: "Apache".to_string(),
                    category: TechCategory::Server,
                    version: self.extract_version(&server_lower, "apache/"),
                    confidence: Confidence::High,
                });
            }

            if server_lower.contains("cloudflare") {
                detected.insert(DetectedTechnology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::CDN,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        // Cloudflare detection
        if response.header("cf-ray").is_some() || response.header("cf-cache-status").is_some() {
            detected.insert(DetectedTechnology {
                name: "Cloudflare".to_string(),
                category: TechCategory::CDN,
                version: None,
                confidence: Confidence::High,
            });
        }

        // CloudFront detection
        if response.header("x-amz-cf-id").is_some() || response.header("x-amz-cf-pop").is_some() {
            detected.insert(DetectedTechnology {
                name: "Amazon CloudFront".to_string(),
                category: TechCategory::CDN,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Akamai detection
        if response.header("x-akamai-transformed").is_some() {
            detected.insert(DetectedTechnology {
                name: "Akamai".to_string(),
                category: TechCategory::CDN,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Vercel detection
        if response.header("x-vercel-id").is_some() || response.header("x-vercel-cache").is_some() {
            detected.insert(DetectedTechnology {
                name: "Vercel".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Netlify detection
        if response.header("x-nf-request-id").is_some() {
            detected.insert(DetectedTechnology {
                name: "Netlify".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // X-Powered-By header
        if let Some(powered_by) = response.header("x-powered-by") {
            let pb_lower = powered_by.to_lowercase();

            if pb_lower.contains("php") {
                detected.insert(DetectedTechnology {
                    name: "PHP".to_string(),
                    category: TechCategory::Language,
                    version: self.extract_version(&pb_lower, "php/"),
                    confidence: Confidence::High,
                });
            }

            if pb_lower.contains("express") {
                detected.insert(DetectedTechnology {
                    name: "Express".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            }

            if pb_lower.contains("asp.net") {
                detected.insert(DetectedTechnology {
                    name: "ASP.NET".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        detected
    }

    /// Detect technologies from HTML content
    fn detect_from_html(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let body_lower = response.body.to_lowercase();

        // Next.js detection
        if body_lower.contains("__next") || body_lower.contains("_next/") || body_lower.contains("__next_data__") {
            detected.insert(DetectedTechnology {
                name: "Next.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::High,
            });
        }

        // React detection
        if body_lower.contains("react") || body_lower.contains("__react") || body_lower.contains("data-reactroot") {
            detected.insert(DetectedTechnology {
                name: "React".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Vue.js detection
        if body_lower.contains("vue.js") || body_lower.contains("data-v-") || body_lower.contains("__vue__") {
            detected.insert(DetectedTechnology {
                name: "Vue.js".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Angular detection
        if body_lower.contains("ng-version") || body_lower.contains("_nghost") || body_lower.contains("ng-app") {
            detected.insert(DetectedTechnology {
                name: "Angular".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // WordPress detection
        if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
            detected.insert(DetectedTechnology {
                name: "WordPress".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Drupal detection
        if body_lower.contains("drupal") || body_lower.contains("/sites/default/files") {
            detected.insert(DetectedTechnology {
                name: "Drupal".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Bootstrap detection
        if body_lower.contains("bootstrap") {
            detected.insert(DetectedTechnology {
                name: "Bootstrap".to_string(),
                category: TechCategory::CSS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Tailwind CSS detection
        if body_lower.contains("tailwind") || body_lower.contains("tw-") {
            detected.insert(DetectedTechnology {
                name: "Tailwind CSS".to_string(),
                category: TechCategory::CSS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // jQuery detection
        if body_lower.contains("jquery") {
            detected.insert(DetectedTechnology {
                name: "jQuery".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Google Analytics
        if body_lower.contains("google-analytics") || body_lower.contains("gtag") || body_lower.contains("ga.js") {
            detected.insert(DetectedTechnology {
                name: "Google Analytics".to_string(),
                category: TechCategory::Analytics,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Cloudflare Pages
        if body_lower.contains("pages.dev") || body_lower.contains("cloudflare-pages") {
            detected.insert(DetectedTechnology {
                name: "Cloudflare Pages".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        // AWS S3
        if body_lower.contains("s3.amazonaws.com") || body_lower.contains("s3-") {
            detected.insert(DetectedTechnology {
                name: "Amazon S3".to_string(),
                category: TechCategory::CloudProvider,
                version: None,
                confidence: Confidence::High,
            });
        }

        detected
    }

    /// Detect technologies from JavaScript files
    fn detect_from_scripts(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();
        let body = &response.body;

        // Check for common JS framework patterns in inline scripts
        if body.contains("webpack") || body.contains("__webpack") {
            detected.insert(DetectedTechnology {
                name: "Webpack".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        if body.contains("vite") || body.contains("/@vite/") {
            detected.insert(DetectedTechnology {
                name: "Vite".to_string(),
                category: TechCategory::JavaScript,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        detected
    }

    /// Detect technologies from cookies
    fn detect_from_cookies(&self, response: &HttpResponse) -> HashSet<DetectedTechnology> {
        let mut detected = HashSet::new();

        if let Some(cookies) = response.header("set-cookie") {
            let cookies_lower = cookies.to_lowercase();

            // Laravel detection
            if cookies_lower.contains("laravel_session") {
                detected.insert(DetectedTechnology {
                    name: "Laravel".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            }

            // Django detection
            if cookies_lower.contains("sessionid") && cookies_lower.contains("csrftoken") {
                detected.insert(DetectedTechnology {
                    name: "Django".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::Medium,
                });
            }

            // ASP.NET detection
            if cookies_lower.contains("asp.net_sessionid") || cookies_lower.contains("__requestverificationtoken") {
                detected.insert(DetectedTechnology {
                    name: "ASP.NET".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        detected
    }

    /// Extract version from string
    fn extract_version(&self, text: &str, prefix: &str) -> Option<String> {
        if let Some(start) = text.find(prefix) {
            let version_start = start + prefix.len();
            let version_str = &text[version_start..];

            // Extract until space or non-version character
            let version = version_str
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>();

            if !version.is_empty() {
                return Some(version);
            }
        }

        None
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
    }
}
