// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Optimized Payload Manager
 * Lazy loading, deduplication, and zero-copy sharing with Arc<str>
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use std::sync::Arc;
use std::sync::OnceLock;
use ahash::AHashSet;

/// Thread-safe lazy-initialized payload cache using Arc<str> for zero-copy sharing
static XSS_PAYLOADS_FAST: OnceLock<Vec<Arc<str>>> = OnceLock::new();
static XSS_PAYLOADS_COMPREHENSIVE: OnceLock<Vec<Arc<str>>> = OnceLock::new();
static SQLI_PAYLOADS_FAST: OnceLock<Vec<Arc<str>>> = OnceLock::new();
static SQLI_PAYLOADS_COMPREHENSIVE: OnceLock<Vec<Arc<str>>> = OnceLock::new();
static PATH_TRAVERSAL_PAYLOADS: OnceLock<Vec<Arc<str>>> = OnceLock::new();
static COMMAND_INJECTION_PAYLOADS: OnceLock<Vec<Arc<str>>> = OnceLock::new();

/// Get XSS payloads with lazy initialization and deduplication
pub fn get_xss_payloads(mode: &str) -> Vec<Arc<str>> {
    match mode {
        "comprehensive" | "insane" => {
            XSS_PAYLOADS_COMPREHENSIVE.get_or_init(|| {
                let raw_payloads = crate::payloads_comprehensive::get_xss_payloads(mode);
                deduplicate_and_intern(raw_payloads)
            }).clone()
        }
        _ => {
            XSS_PAYLOADS_FAST.get_or_init(|| {
                let raw_payloads = crate::payloads_comprehensive::get_xss_payloads("fast");
                deduplicate_and_intern(raw_payloads)
            }).clone()
        }
    }
}

/// Get SQLi payloads with lazy initialization and deduplication
pub fn get_sqli_payloads(mode: &str) -> Vec<Arc<str>> {
    match mode {
        "comprehensive" | "insane" => {
            SQLI_PAYLOADS_COMPREHENSIVE.get_or_init(|| {
                let raw_payloads = crate::payloads_comprehensive::get_sqli_payloads(mode);
                deduplicate_and_intern(raw_payloads)
            }).clone()
        }
        _ => {
            SQLI_PAYLOADS_FAST.get_or_init(|| {
                let raw_payloads = crate::payloads_comprehensive::get_sqli_payloads("fast");
                deduplicate_and_intern(raw_payloads)
            }).clone()
        }
    }
}

/// Get path traversal payloads with lazy initialization
pub fn get_path_traversal_payloads() -> Vec<Arc<str>> {
    PATH_TRAVERSAL_PAYLOADS.get_or_init(|| {
        let raw_payloads = crate::payloads::get_path_traversal_payloads();
        deduplicate_and_intern(raw_payloads)
    }).clone()
}

/// Get command injection payloads with lazy initialization
pub fn get_command_injection_payloads() -> Vec<Arc<str>> {
    COMMAND_INJECTION_PAYLOADS.get_or_init(|| {
        let raw_payloads = crate::payloads::get_command_injection_payloads();
        deduplicate_and_intern(raw_payloads)
    }).clone()
}

/// Deduplicate payloads and intern as Arc<str> for zero-copy sharing
fn deduplicate_and_intern(payloads: Vec<String>) -> Vec<Arc<str>> {
    let mut seen = AHashSet::with_capacity(payloads.len());
    let mut result = Vec::with_capacity(payloads.len());

    for payload in payloads {
        if seen.insert(payload.clone()) {
            result.push(Arc::<str>::from(payload.as_str()));
        }
    }

    result.shrink_to_fit();
    result
}

/// Smart payload selector based on target characteristics
pub struct SmartPayloadSelector {
    framework: Option<String>,
    detected_waf: bool,
}

impl SmartPayloadSelector {
    pub fn new() -> Self {
        Self {
            framework: None,
            detected_waf: false,
        }
    }

    pub fn with_framework(mut self, framework: String) -> Self {
        self.framework = Some(framework);
        self
    }

    pub fn with_waf_detection(mut self, detected: bool) -> Self {
        self.detected_waf = detected;
        self
    }

    /// Select optimal payloads based on target characteristics
    pub fn select_xss_payloads(&self, mode: &str) -> Vec<Arc<str>> {
        let mut payloads = get_xss_payloads(mode);

        if self.detected_waf {
            payloads = payloads.into_iter()
                .filter(|p| self.is_waf_bypass_payload(p))
                .collect();
        }

        if let Some(ref framework) = self.framework {
            payloads.extend(self.get_framework_specific_xss(framework));
        }

        payloads
    }

    /// Select optimal SQLi payloads based on target
    pub fn select_sqli_payloads(&self, mode: &str) -> Vec<Arc<str>> {
        let mut payloads = get_sqli_payloads(mode);

        if self.detected_waf {
            payloads = payloads.into_iter()
                .filter(|p| self.is_sqli_waf_bypass(p))
                .collect();
        }

        if let Some(ref framework) = self.framework {
            payloads.extend(self.get_framework_specific_sqli(framework));
        }

        payloads
    }

    fn is_waf_bypass_payload(&self, payload: &str) -> bool {
        payload.contains("/**/")
            || payload.contains("%0a")
            || payload.contains("%0d")
            || payload.contains("&#")
    }

    fn is_sqli_waf_bypass(&self, payload: &str) -> bool {
        payload.contains("/**/")
            || payload.contains("--+")
            || payload.contains("%0a")
    }

    fn get_framework_specific_xss(&self, framework: &str) -> Vec<Arc<str>> {
        match framework.to_lowercase().as_str() {
            "react" => vec![
                Arc::<str>::from("javascript:alert(1)"),
                Arc::<str>::from("dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}"),
            ],
            "angular" => vec![
                Arc::<str>::from("{{constructor.constructor('alert(1)')()}}"),
                Arc::<str>::from("{{$on.constructor('alert(1)')()}}"),
            ],
            "vue" => vec![
                Arc::<str>::from("<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>"),
            ],
            _ => Vec::new(),
        }
    }

    fn get_framework_specific_sqli(&self, framework: &str) -> Vec<Arc<str>> {
        match framework.to_lowercase().as_str() {
            "mysql" => vec![
                Arc::<str>::from("' AND SLEEP(5)--"),
                Arc::<str>::from("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
            ],
            "postgresql" => vec![
                Arc::<str>::from("' AND pg_sleep(5)--"),
                Arc::<str>::from("'; SELECT pg_sleep(5)--"),
            ],
            "mssql" => vec![
                Arc::<str>::from("' WAITFOR DELAY '00:00:05'--"),
                Arc::<str>::from("'; WAITFOR DELAY '00:00:05'--"),
            ],
            "oracle" => vec![
                Arc::<str>::from("' AND DBMS_LOCK.SLEEP(5)--"),
            ],
            _ => Vec::new(),
        }
    }
}

impl Default for SmartPayloadSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_deduplication() {
        let payloads = vec![
            "payload1".to_string(),
            "payload2".to_string(),
            "payload1".to_string(), // duplicate
            "payload3".to_string(),
        ];

        let result = deduplicate_and_intern(payloads);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_arc_str_sharing() {
        let payloads = get_xss_payloads("fast");
        let cloned = payloads.clone();

        // Cloning Arc<str> is cheap (pointer copy)
        assert_eq!(payloads.len(), cloned.len());
    }

    #[test]
    fn test_smart_selector() {
        let selector = SmartPayloadSelector::new()
            .with_framework("react".to_string())
            .with_waf_detection(true);

        let xss_payloads = selector.select_xss_payloads("fast");
        assert!(!xss_payloads.is_empty());
    }
}
