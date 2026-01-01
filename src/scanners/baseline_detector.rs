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
                    baseline_response: None,
                    similarity_score: 0.0,
                };
            }
        };

        let response2 = match self.http_client.get(&random_url).await {
            Ok(r) => r,
            Err(_) => {
                return BaselineResult {
                    is_static_responder: false,
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
                body.contains("__apollo");  // Apollo state

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
            baseline_response: Some(response1),
            similarity_score: avg_similarity,
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
        let content_similarity = Self::calculate_content_similarity(
            &response_a.body,
            &response_b.body,
        );

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

        assert!(BaselineDetector::responses_are_different(&resp1, &resp2, 0.85));
    }
}
