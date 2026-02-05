// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Baseline Response Detector
 * Detects sites that respond identically to all requests (false positive prevention)
 *
 * Many AWS/CDN/proxy sites return 200 OK for everything, causing false positives.
 * This module tests if a site's behavior is consistent across different request types.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::{HttpClient, HttpResponse};
use std::sync::Arc;
use tracing::debug;

/// Baseline detection result
#[derive(Debug, Clone)]
pub struct BaselineResult {
    /// Whether the site appears to respond identically to all requests
    pub is_static_responder: bool,
    /// Whether the site is a parked/placeholder domain (GoDaddy, Sedo, etc.)
    pub is_parked_site: bool,
    /// Name of the parking service detected (e.g., "GoDaddy", "Sedo", "Bodis")
    pub parking_service: Option<String>,
    /// The baseline response (if static responder)
    pub baseline_response: Option<HttpResponse>,
    /// Similarity score (0.0 - 1.0, where 1.0 = identical responses)
    pub similarity_score: f64,
}

pub struct BaselineDetector {
    http_client: Arc<HttpClient>,
}

impl BaselineDetector {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Test if a URL responds identically to different requests
    ///
    /// Returns true if the site is a "static responder" (always same response)
    pub async fn is_static_responder(&self, url: &str) -> BaselineResult {
        // PREMIUM FEATURE: Baseline Detector requires Professional license
        if !crate::license::is_feature_available("baseline_detector") {
            return BaselineResult {
                is_static_responder: false,
                is_parked_site: false,
                parking_service: None,
                baseline_response: None,
                similarity_score: 0.0,
            };
        }
        // Send 3 different requests:
        // 1. Normal request
        // 2. Request with random parameter
        // 3. Request with obviously invalid parameter

        let normal_url = url.to_string();
        let random_url = format!(
            "{}{}param_{}=value_{}",
            url,
            if url.contains('?') { "&" } else { "?" },
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string()
        );
        let invalid_url = format!(
            "{}{}invalid_test_param_xyz=<script>alert(1)</script>",
            url,
            if url.contains('?') { "&" } else { "?" }
        );

        // Get responses
        let response1 = match self.http_client.get(&normal_url).await {
            Ok(r) => r,
            Err(_) => {
                return BaselineResult {
                    is_static_responder: false,
                    is_parked_site: false,
                    parking_service: None,
                    baseline_response: None,
                    similarity_score: 0.0,
                };
            }
        };

        // Check for parked/placeholder site FIRST (before static responder check)
        // Parked sites should be detected regardless of similarity score
        let (is_parked, parking_service) = Self::detect_parked_site(&response1);

        if is_parked {
            debug!(
                "PARKED SITE DETECTED: {} - parking service: {}",
                url,
                parking_service.as_deref().unwrap_or("unknown")
            );
            return BaselineResult {
                is_static_responder: true,
                is_parked_site: true,
                parking_service,
                baseline_response: Some(response1),
                similarity_score: 1.0,
            };
        }

        let response2 = match self.http_client.get(&random_url).await {
            Ok(r) => r,
            Err(_) => {
                return BaselineResult {
                    is_static_responder: false,
                    is_parked_site: false,
                    parking_service: None,
                    baseline_response: Some(response1.clone()),
                    similarity_score: 0.5,
                };
            }
        };

        let response3 = match self.http_client.get(&invalid_url).await {
            Ok(r) => r,
            Err(_) => {
                return BaselineResult {
                    is_static_responder: false,
                    is_parked_site: false,
                    parking_service: None,
                    baseline_response: Some(response1.clone()),
                    similarity_score: 0.5,
                };
            }
        };

        // Compare responses
        let sim_1_2 = Self::calculate_similarity(&response1, &response2);
        let sim_1_3 = Self::calculate_similarity(&response1, &response3);
        let sim_2_3 = Self::calculate_similarity(&response2, &response3);

        let avg_similarity = (sim_1_2 + sim_1_3 + sim_2_3) / 3.0;

        debug!(
            "Baseline detection: similarity scores: 1-2={:.2}, 1-3={:.2}, 2-3={:.2}, avg={:.2}",
            sim_1_2, sim_1_3, sim_2_3, avg_similarity
        );

        // If all responses are > 95% similar, it might be a static responder
        // BUT we should check if it's a SPA (Single Page Application) first
        let mut is_static = avg_similarity > 0.95;

        // Check if it's a SPA - SPAs return the same HTML shell for all routes
        // but the actual content is loaded dynamically via JavaScript
        if is_static {
            let body = response1.body.to_lowercase();
            let is_spa = body.contains("id=\"app\"") ||  // Vue/React common
                body.contains("id=\"root\"") ||  // React common
                body.contains("ng-app") ||  // Angular
                body.contains("data-v-") ||  // Vue scoped styles
                body.contains("__nuxt") ||  // Nuxt.js
                body.contains("__next") ||  // Next.js
                body.contains("_app.js") ||  // Next.js
                body.contains("vue.") ||  // Vue.js
                body.contains("react.") ||  // React
                body.contains("angular.") ||  // Angular
                body.contains("/graphql") ||  // GraphQL endpoint reference
                body.contains("apolloclient") ||  // Apollo GraphQL client
                body.contains("__apollo"); // Apollo state

            if is_spa {
                debug!(
                    "SPA DETECTED: Site is a Single Page Application - not treating as static responder despite {:.1}% similarity",
                    avg_similarity * 100.0
                );
                is_static = false;
            }
        }

        if is_static {
            debug!(
                "STATIC RESPONDER DETECTED: Site responds identically ({:.1}% similarity) to all requests",
                avg_similarity * 100.0
            );
        }

        BaselineResult {
            is_static_responder: is_static,
            is_parked_site: false,
            parking_service: None,
            baseline_response: Some(response1),
            similarity_score: avg_similarity,
        }
    }

    /// Detect if a site is a parked/placeholder domain
    ///
    /// Checks response body and headers for known domain parking service indicators.
    /// These sites produce massive false positives because they respond to any path/parameter
    /// with a generic landing page, ads, or "domain for sale" content.
    ///
    /// Known parking services detected:
    /// - GoDaddy Parking (afternic.com, godaddy.com parking pages)
    /// - Sedo (sedo.com domain marketplace)
    /// - Bodis (bodis.com parking)
    /// - ParkingCrew / DomainSponsor
    /// - Sedoparking
    /// - Dan.com (domain marketplace)
    /// - Hugedomains
    /// - Namecheap parking
    /// - Google Domains parking
    /// - Ionos/1&1 parking
    /// - Hostinger parking
    /// - Generic "domain for sale" pages
    /// - Generic "under construction" placeholder pages
    pub fn detect_parked_site(response: &HttpResponse) -> (bool, Option<String>) {
        let body = response.body.to_lowercase();
        let body_len = body.len();

        // Short-circuit: very large pages are unlikely to be parked sites
        // Parked pages are typically small (< 100KB)
        if body_len > 100_000 {
            return (false, None);
        }

        // =====================================================================
        // CHECK HTTP HEADERS for parking service indicators
        // =====================================================================
        for (key, value) in &response.headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            // GoDaddy parking headers
            if key_lower == "server" && value_lower.contains("parking") {
                return (true, Some("GoDaddy Parking".to_string()));
            }

            // Sedoparking headers
            if (key_lower == "x-powered-by" || key_lower == "server")
                && value_lower.contains("sedoparking")
            {
                return (true, Some("Sedo".to_string()));
            }

            // Bodis parking headers
            if key_lower == "server" && value_lower.contains("bodis") {
                return (true, Some("Bodis".to_string()));
            }

            // ParkingCrew
            if value_lower.contains("parkingcrew") {
                return (true, Some("ParkingCrew".to_string()));
            }
        }

        // =====================================================================
        // CHECK BODY CONTENT for parking service patterns
        // =====================================================================
        // We use a scoring system to avoid false positives from a single match.
        // A site needs multiple parking indicators to be classified as parked.

        let mut parking_score: u32 = 0;
        let mut detected_service: Option<String> = None;

        // --- GoDaddy Parking (most common) ---
        // GoDaddy parked pages typically contain references to afternic.com,
        // godaddy.com parking, or specific GoDaddy parking page patterns
        if body.contains("afternic.com") {
            parking_score += 3;
            detected_service = Some("GoDaddy/Afternic".to_string());
        }
        if body.contains("godaddy.com/parking") || body.contains("godaddy parking") {
            parking_score += 3;
            detected_service = Some("GoDaddy Parking".to_string());
        }
        if body.contains("img1.wsimg.com") || body.contains("img1.wsimg") {
            // GoDaddy's image CDN used on parking pages
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("GoDaddy Parking".to_string());
            }
        }
        if body.contains("parkweb.godaddy") || body.contains("park.godaddy") {
            parking_score += 3;
            detected_service = Some("GoDaddy Parking".to_string());
        }
        if body.contains("domaincontrol.com") {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("GoDaddy Parking".to_string());
            }
        }

        // --- Sedo Parking ---
        if body.contains("sedo.com") {
            parking_score += 3;
            detected_service = Some("Sedo".to_string());
        }
        if body.contains("sedoparking.com") || body.contains("sedoparking") {
            parking_score += 3;
            detected_service = Some("Sedo".to_string());
        }

        // --- Bodis Parking ---
        if body.contains("bodis.com") {
            parking_score += 3;
            detected_service = Some("Bodis".to_string());
        }
        if body.contains("bodiscdn.com") || body.contains("bodis-cdn") {
            parking_score += 3;
            detected_service = Some("Bodis".to_string());
        }

        // --- Dan.com (domain marketplace) ---
        if body.contains("dan.com") && (body.contains("domain") || body.contains("buy")) {
            parking_score += 3;
            detected_service = Some("Dan.com".to_string());
        }

        // --- ParkingCrew / DomainSponsor ---
        if body.contains("parkingcrew.net") || body.contains("parkingcrew.com") {
            parking_score += 3;
            detected_service = Some("ParkingCrew".to_string());
        }
        if body.contains("domainsponsor.com") {
            parking_score += 3;
            detected_service = Some("DomainSponsor".to_string());
        }

        // --- HugeDomains ---
        if body.contains("hugedomains.com") {
            parking_score += 3;
            detected_service = Some("HugeDomains".to_string());
        }

        // --- Namecheap Parking ---
        if body.contains("namecheap.com")
            && (body.contains("parked") || body.contains("parking") || body.contains("for sale"))
        {
            parking_score += 3;
            detected_service = Some("Namecheap Parking".to_string());
        }

        // --- Ionos/1&1 Parking ---
        if body.contains("ionos.com") && body.contains("placeholder") {
            parking_score += 3;
            detected_service = Some("IONOS Parking".to_string());
        }

        // --- Hostinger Parking ---
        if body.contains("hostinger") && (body.contains("parked") || body.contains("coming soon"))
        {
            parking_score += 3;
            detected_service = Some("Hostinger Parking".to_string());
        }

        // --- Porkbun Parking ---
        if body.contains("porkbun.com") && body.contains("parked") {
            parking_score += 3;
            detected_service = Some("Porkbun Parking".to_string());
        }

        // --- Dynadot Parking ---
        if body.contains("dynadot.com") && body.contains("parked") {
            parking_score += 3;
            detected_service = Some("Dynadot Parking".to_string());
        }

        // --- Google Domains / Squarespace Parking ---
        if body.contains("domains.google") && body.contains("parked") {
            parking_score += 3;
            detected_service = Some("Google Domains Parking".to_string());
        }

        // --- Epik Parking ---
        if body.contains("epik.com") && (body.contains("parked") || body.contains("for sale")) {
            parking_score += 3;
            detected_service = Some("Epik Parking".to_string());
        }

        // =====================================================================
        // GENERIC PARKING/PLACEHOLDER INDICATORS
        // =====================================================================
        // These are less specific and need higher combined scores

        // "Domain for sale" indicators
        if body.contains("domain is for sale") || body.contains("this domain is for sale") {
            parking_score += 3;
            if detected_service.is_none() {
                detected_service = Some("Domain For Sale Page".to_string());
            }
        }
        if body.contains("buy this domain") || body.contains("purchase this domain") {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("Domain For Sale Page".to_string());
            }
        }
        if body.contains("domain may be for sale") {
            parking_score += 3;
            if detected_service.is_none() {
                detected_service = Some("Domain For Sale Page".to_string());
            }
        }
        if body.contains("make an offer") && body.contains("domain") {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("Domain Marketplace".to_string());
            }
        }

        // Generic parked domain indicators
        if body.contains("parked domain") || body.contains("parked page") {
            parking_score += 3;
            if detected_service.is_none() {
                detected_service = Some("Generic Parking".to_string());
            }
        }
        if body.contains("domain parking") {
            parking_score += 3;
            if detected_service.is_none() {
                detected_service = Some("Generic Parking".to_string());
            }
        }

        // "Coming soon" / "Under construction" with no real content
        // These need additional context to avoid false positives on real sites
        let has_coming_soon = body.contains("coming soon") || body.contains("under construction");
        let has_minimal_content = body_len < 5_000;
        let has_no_nav = !body.contains("<nav") && !body.contains("class=\"nav");
        let has_no_forms = !body.contains("<form");
        if has_coming_soon && has_minimal_content && has_no_nav && has_no_forms {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("Placeholder Page".to_string());
            }
        }

        // Default/blank hosting pages
        if (body.contains("website coming soon")
            || body.contains("site under construction")
            || body.contains("future home of"))
            && has_minimal_content
        {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("Hosting Default Page".to_string());
            }
        }

        // Parking-specific ad networks (commonly injected into parked pages)
        if body.contains("parklogic.com") || body.contains("above.com") {
            parking_score += 2;
            if detected_service.is_none() {
                detected_service = Some("Ad-Based Parking".to_string());
            }
        }

        // =====================================================================
        // TITLE-BASED DETECTION
        // =====================================================================
        // Extract <title> content for additional signals
        if let Some(title_start) = body.find("<title") {
            if let Some(title_content_start) = body[title_start..].find('>') {
                let title_begin = title_start + title_content_start + 1;
                if let Some(title_end) = body[title_begin..].find("</title>") {
                    let title = &body[title_begin..title_begin + title_end];
                    let title = title.trim();

                    // Titles like "parked domain", "domain for sale", etc.
                    if title.contains("parked")
                        || title.contains("domain for sale")
                        || title.contains("domain is for sale")
                        || title.contains("buy this domain")
                    {
                        parking_score += 2;
                    }

                    // Very generic/empty titles on small pages (hosting defaults)
                    if has_minimal_content
                        && (title.is_empty()
                            || title == "website"
                            || title == "home"
                            || title == "welcome"
                            || title == "coming soon"
                            || title == "under construction"
                            || title == "page"
                            || title == "site")
                    {
                        parking_score += 1;
                    }
                }
            }
        }

        // =====================================================================
        // DECISION: Threshold-based classification
        // =====================================================================
        // Score >= 3: High confidence parking detection (specific service match)
        // This prevents false positives from a single generic keyword match

        if parking_score >= 3 {
            debug!(
                "Parked site detected with score {}: service={:?}",
                parking_score, detected_service
            );
            (true, detected_service)
        } else {
            (false, None)
        }
    }

    /// Compare two responses and test if they behave differently
    ///
    /// Used to verify that a vulnerability actually causes a different response
    pub fn responses_are_different(
        response_a: &HttpResponse,
        response_b: &HttpResponse,
        threshold: f64,
    ) -> bool {
        let similarity = Self::calculate_similarity(response_a, response_b);
        similarity < threshold
    }

    /// Calculate similarity between two HTTP responses
    ///
    /// Returns 0.0 (completely different) to 1.0 (identical)
    fn calculate_similarity(response_a: &HttpResponse, response_b: &HttpResponse) -> f64 {
        // Factor 1: Status code match (30% weight)
        let status_similarity = if response_a.status_code == response_b.status_code {
            1.0
        } else {
            0.0
        };

        // Factor 2: Body length similarity (30% weight)
        let len_a = response_a.body.len() as f64;
        let len_b = response_b.body.len() as f64;
        let max_len = len_a.max(len_b);
        let min_len = len_a.min(len_b);

        let length_similarity = if max_len == 0.0 {
            1.0
        } else {
            min_len / max_len
        };

        // Factor 3: Content similarity (40% weight)
        let content_similarity =
            Self::calculate_content_similarity(&response_a.body, &response_b.body);

        (status_similarity * 0.30) + (length_similarity * 0.30) + (content_similarity * 0.40)
    }

    /// Calculate content similarity using character-level comparison
    fn calculate_content_similarity(text_a: &str, text_b: &str) -> f64 {
        if text_a.is_empty() && text_b.is_empty() {
            return 1.0;
        }

        if text_a.is_empty() || text_b.is_empty() {
            return 0.0;
        }

        // For performance, compare first 5000 characters
        let sample_a = if text_a.len() > 5000 {
            &text_a[..5000]
        } else {
            text_a
        };
        let sample_b = if text_b.len() > 5000 {
            &text_b[..5000]
        } else {
            text_b
        };

        // Count matching characters in the same positions
        let matches = sample_a
            .chars()
            .zip(sample_b.chars())
            .filter(|(a, b)| a == b)
            .count();

        let max_len = sample_a.len().max(sample_b.len());

        if max_len == 0 {
            1.0
        } else {
            matches as f64 / max_len as f64
        }
    }

    /// Extract evidence from response for vulnerability reporting
    pub fn extract_evidence(
        response: &HttpResponse,
        evidence_type: &str,
        max_length: usize,
    ) -> String {
        match evidence_type {
            "headers" => {
                format!("Response Headers:\n{:#?}", response.headers)
            }
            "body_snippet" => {
                let snippet = if response.body.len() > max_length {
                    format!("{}... [truncated]", &response.body[..max_length])
                } else {
                    response.body.clone()
                };
                format!("Response Body:\n{}", snippet)
            }
            "status" => {
                format!("Status Code: {}", response.status_code)
            }
            "full" => {
                let body_snippet = if response.body.len() > max_length {
                    format!("{}... [truncated]", &response.body[..max_length])
                } else {
                    response.body.clone()
                };
                format!(
                    "Status: {}\nHeaders: {:#?}\nBody:\n{}",
                    response.status_code, response.headers, body_snippet
                )
            }
            _ => String::new(),
        }
    }
}

// UUID generation
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
    fn test_identical_responses() {
        let resp1 = HttpResponse {
            status_code: 200,
            body: "Hello World".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let resp2 = HttpResponse {
            status_code: 200,
            body: "Hello World".to_string(),
            headers: HashMap::new(),
            duration_ms: 105,
        };

        let similarity = BaselineDetector::calculate_similarity(&resp1, &resp2);
        assert!(similarity > 0.99);
    }

    #[test]
    fn test_different_responses() {
        let resp1 = HttpResponse {
            status_code: 200,
            body: "Hello World".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let resp2 = HttpResponse {
            status_code: 404,
            body: "Not Found".to_string(),
            headers: HashMap::new(),
            duration_ms: 50,
        };

        let similarity = BaselineDetector::calculate_similarity(&resp1, &resp2);
        assert!(similarity < 0.5);
    }

    #[test]
    fn test_responses_are_different() {
        let resp1 = HttpResponse {
            status_code: 200,
            body: "Normal response".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let resp2 = HttpResponse {
            status_code: 200,
            body: "SQL error: syntax error at position 5".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(BaselineDetector::responses_are_different(
            &resp1, &resp2, 0.85
        ));
    }

    // =====================================================================
    // Parked Site Detection Tests
    // =====================================================================

    #[test]
    fn test_godaddy_parked_site() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>Domain For Sale</title></head><body>\
                   <div>This domain is parked by GoDaddy</div>\
                   <a href=\"https://afternic.com/domain/example.com\">Buy this domain</a>\
                   <script src=\"https://img1.wsimg.com/parking.js\"></script>\
                   </body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect GoDaddy parked site");
        let service_name = service.unwrap();
        assert!(
            service_name.contains("GoDaddy") || service_name.contains("Afternic"),
            "Should identify GoDaddy/Afternic as parking service, got: {}",
            service_name
        );
    }

    #[test]
    fn test_sedo_parked_site() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>sedoparking</title></head><body>\
                   <div>This domain is for sale on sedo.com</div>\
                   <a href=\"https://sedo.com\">Buy domain</a>\
                   </body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect Sedo parked site");
        assert_eq!(service.unwrap(), "Sedo");
    }

    #[test]
    fn test_bodis_parked_site() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><body><script src=\"https://bodiscdn.com/park.js\"></script>\
                   <div>Domain parking by bodis.com</div></body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect Bodis parked site");
        assert_eq!(service.unwrap(), "Bodis");
    }

    #[test]
    fn test_generic_domain_for_sale() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>Domain For Sale</title></head><body>\
                   <h1>This domain is for sale</h1>\
                   <p>Buy this domain now! Make an offer for this domain.</p>\
                   </body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect generic domain-for-sale page");
        assert!(service.is_some());
    }

    #[test]
    fn test_parking_header_detection() {
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Parking/1.0".to_string());

        let resp = HttpResponse {
            status_code: 200,
            body: "<html><body>Welcome</body></html>".to_string(),
            headers,
            duration_ms: 100,
        };

        let (is_parked, _service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect parking via Server header");
    }

    #[test]
    fn test_real_website_not_parked() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>My Real Website</title></head><body>\
                   <nav><a href=\"/about\">About</a><a href=\"/contact\">Contact</a></nav>\
                   <div id=\"app\"><h1>Welcome to my site</h1>\
                   <form action=\"/login\" method=\"post\">\
                   <input name=\"email\" type=\"email\"/>\
                   <button type=\"submit\">Login</button></form>\
                   <p>Lots of real content here with actual useful information...</p>\
                   </div></body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, _) = BaselineDetector::detect_parked_site(&resp);
        assert!(!is_parked, "Should NOT flag real website as parked");
    }

    #[test]
    fn test_large_page_not_parked() {
        // Generate a page > 100KB
        let body = "x".repeat(150_000);
        let resp = HttpResponse {
            status_code: 200,
            body,
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, _) = BaselineDetector::detect_parked_site(&resp);
        assert!(
            !is_parked,
            "Should NOT flag large pages as parked (short-circuit)"
        );
    }

    #[test]
    fn test_hugedomains_parked_site() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><body><h1>This domain is for sale</h1>\
                   <p>Buy at hugedomains.com</p></body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect HugeDomains parked site");
        assert_eq!(service.unwrap(), "HugeDomains");
    }

    #[test]
    fn test_dan_com_parked_site() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><body><h1>This domain is for sale</h1>\
                   <p>Buy this domain on dan.com</p></body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect Dan.com parked site");
        assert_eq!(service.unwrap(), "Dan.com");
    }

    #[test]
    fn test_sedoparking_header() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Powered-By".to_string(),
            "SedoParking/2.0".to_string(),
        );

        let resp = HttpResponse {
            status_code: 200,
            body: "<html><body>Domain page</body></html>".to_string(),
            headers,
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect Sedo via X-Powered-By header");
        assert_eq!(service.unwrap(), "Sedo");
    }

    #[test]
    fn test_parked_domain_text() {
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>parked domain</title></head><body>\
                   <h1>This is a parked domain</h1>\
                   <p>Domain parking provided by example registrar.</p>\
                   </body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, service) = BaselineDetector::detect_parked_site(&resp);
        assert!(is_parked, "Should detect 'parked domain' text");
        assert!(service.is_some());
    }

    #[test]
    fn test_ecommerce_site_with_domain_word_not_parked() {
        // A real e-commerce site that happens to mention "domain" shouldn't be flagged
        let resp = HttpResponse {
            status_code: 200,
            body: "<html><head><title>Domain Name Services - GoDaddy</title></head><body>\
                   <nav><a href=\"/domains\">Domains</a><a href=\"/hosting\">Hosting</a></nav>\
                   <form action=\"/search\" method=\"get\">\
                   <input name=\"domain\" placeholder=\"Find your domain\"/>\
                   <button>Search</button></form>\
                   <div>Browse millions of domains from our marketplace. \
                   Register your domain today with our competitive pricing. \
                   Thousands of extensions available including .com, .net, .org.\
                   Professional email, websites, and more.</div>\
                   </body></html>"
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let (is_parked, _) = BaselineDetector::detect_parked_site(&resp);
        assert!(
            !is_parked,
            "Real website mentioning domains should NOT be flagged as parked"
        );
    }
}
