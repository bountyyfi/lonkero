// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Security Scanner - Exclusion Validator
 * Fast Rust-based exclusion checking for targets and assets
 *
 * Features:
 * - IP/CIDR range matching
 * - Domain pattern matching (wildcards and regex)
 * - Scanner-specific exclusions
 * - Time window validation
 * - High-performance validation for scan pipelines
 *
 * Copyright 2025 Bountyy Oy
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use regex::Regex;
use chrono::{Utc, Datelike, Weekday, NaiveTime};
use serde::{Deserialize, Serialize};

/// Exclusion rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRule {
    pub id: i32,
    pub rule_type: String,
    pub pattern: String,
    pub action: String,
    pub scanner_types: Vec<String>,
    pub time_window: Option<TimeWindow>,
    pub is_active: bool,
    pub priority: i32,
}

/// Time window for time-based exclusions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: String,  // HH:MM format
    pub end: String,    // HH:MM format
    pub days: Vec<String>, // ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
    pub timezone: Option<String>, // Default: UTC
}

/// Exclusion validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_excluded: bool,
    pub matched_rules: Vec<MatchedRule>,
    pub action: String, // 'exclude', 'alert', 'warn', 'allow'
}

/// Matched exclusion rule details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: i32,
    pub rule_type: String,
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

/// Main exclusion validator
pub struct ExclusionValidator {
    rules: Vec<ExclusionRule>,
}

impl ExclusionValidator {
    /// Create a new validator with rules
    pub fn new(rules: Vec<ExclusionRule>) -> Self {
        // Sort rules by priority (descending)
        let mut sorted_rules = rules;
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        Self {
            rules: sorted_rules,
        }
    }

    /// Validate if a target should be excluded
    pub fn validate(&self, target: &str, scanner_type: Option<&str>) -> ValidationResult {
        let mut matched_rules = Vec::new();
        let mut highest_action = "allow";

        for rule in &self.rules {
            if !rule.is_active {
                continue;
            }

            // Check scanner type filter
            if let Some(scanner) = scanner_type {
                if !rule.scanner_types.is_empty() && !rule.scanner_types.contains(&scanner.to_string()) {
                    continue;
                }
            }

            // Check time window
            if let Some(ref time_window) = rule.time_window {
                if !self.is_within_time_window(time_window) {
                    continue;
                }
            }

            // Check if rule matches target
            if let Some(reason) = self.matches_rule(target, rule) {
                matched_rules.push(MatchedRule {
                    rule_id: rule.id,
                    rule_type: rule.rule_type.clone(),
                    pattern: rule.pattern.clone(),
                    action: rule.action.clone(),
                    reason,
                });

                // Update highest priority action
                highest_action = self.get_highest_action(highest_action, &rule.action);

                // If we hit an exclude action, we can stop checking
                if rule.action == "exclude" {
                    break;
                }
            }
        }

        ValidationResult {
            is_excluded: highest_action == "exclude",
            matched_rules,
            action: highest_action.to_string(),
        }
    }

    /// Check if target matches a specific rule
    fn matches_rule(&self, target: &str, rule: &ExclusionRule) -> Option<String> {
        match rule.rule_type.as_str() {
            "ip" | "cidr" => self.match_ip_cidr(target, &rule.pattern),
            "domain" | "subdomain" => self.match_domain(target, &rule.pattern),
            "pattern" => self.match_pattern(target, &rule.pattern),
            "regex" => self.match_regex(target, &rule.pattern),
            _ => None,
        }
    }

    /// Match IP address or CIDR range
    fn match_ip_cidr(&self, target: &str, pattern: &str) -> Option<String> {
        // Parse target as IP
        let target_ip = match self.extract_ip(target) {
            Some(ip) => ip,
            None => return None,
        };

        // Check if pattern is CIDR notation
        if pattern.contains('/') {
            if self.ip_in_cidr(&target_ip, pattern) {
                return Some(format!("IP {} matches CIDR range {}", target_ip, pattern));
            }
        } else {
            // Direct IP match
            if let Ok(pattern_ip) = IpAddr::from_str(pattern) {
                if target_ip == pattern_ip {
                    return Some(format!("IP {} matches {}", target_ip, pattern));
                }
            }
        }

        None
    }

    /// Match domain pattern (supports wildcards)
    fn match_domain(&self, target: &str, pattern: &str) -> Option<String> {
        let target_domain = self.extract_domain(target);

        // Exact match
        if target_domain.eq_ignore_ascii_case(pattern) {
            return Some(format!("Domain {} matches {}", target_domain, pattern));
        }

        // Wildcard matching
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            if target_domain.eq_ignore_ascii_case(suffix) ||
               target_domain.ends_with(&format!(".{}", suffix)) {
                return Some(format!("Domain {} matches pattern {}", target_domain, pattern));
            }
        }

        // Subdomain matching
        if pattern.starts_with('.') && target_domain.ends_with(pattern) {
            return Some(format!("Domain {} matches subdomain pattern {}", target_domain, pattern));
        }

        None
    }

    /// Match using simple pattern (supports * wildcard)
    fn match_pattern(&self, target: &str, pattern: &str) -> Option<String> {
        // Convert wildcard pattern to regex
        let regex_pattern = pattern
            .replace(".", r"\.")
            .replace("*", ".*");

        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            if re.is_match(target) {
                return Some(format!("Target {} matches pattern {}", target, pattern));
            }
        }

        None
    }

    /// Match using regex pattern
    fn match_regex(&self, target: &str, pattern: &str) -> Option<String> {
        match Regex::new(pattern) {
            Ok(re) => {
                if re.is_match(target) {
                    return Some(format!("Target {} matches regex {}", target, pattern));
                }
            }
            Err(e) => {
                eprintln!("Invalid regex pattern '{}': {}", pattern, e);
            }
        }

        None
    }

    /// Extract IP address from target string
    fn extract_ip(&self, target: &str) -> Option<IpAddr> {
        // Try parsing directly
        if let Ok(ip) = IpAddr::from_str(target) {
            return Some(ip);
        }

        // Try extracting from URL
        if target.contains("://") {
            if let Some(host_part) = target.split("://").nth(1) {
                if let Some(host) = host_part.split('/').next() {
                    // Remove port if present
                    let host_no_port = host.split(':').next().unwrap_or(host);
                    if let Ok(ip) = IpAddr::from_str(host_no_port) {
                        return Some(ip);
                    }
                }
            }
        }

        None
    }

    /// Extract domain from target string
    fn extract_domain(&self, target: &str) -> String {
        let mut domain = target;

        // Remove protocol
        if let Some(idx) = domain.find("://") {
            domain = &domain[idx + 3..];
        }

        // Remove path
        if let Some(idx) = domain.find('/') {
            domain = &domain[..idx];
        }

        // Remove port
        if let Some(idx) = domain.rfind(':') {
            // Make sure it's not an IPv6 address
            if !domain.contains('[') {
                domain = &domain[..idx];
            }
        }

        domain.to_lowercase()
    }

    /// Check if IP is within CIDR range
    fn ip_in_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network_ip = match IpAddr::from_str(parts[0]) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let prefix_len: u8 = match parts[1].parse() {
            Ok(len) => len,
            Err(_) => return false,
        };

        match (ip, network_ip) {
            (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                self.ipv4_in_cidr(ip4, &net4, prefix_len)
            }
            (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
                self.ipv6_in_cidr(ip6, &net6, prefix_len)
            }
            _ => false, // Mismatched IP versions
        }
    }

    /// Check if IPv4 is within CIDR range
    fn ipv4_in_cidr(&self, ip: &Ipv4Addr, network: &Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len > 32 {
            return false;
        }

        let ip_bits = u32::from(*ip);
        let network_bits = u32::from(*network);
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };

        (ip_bits & mask) == (network_bits & mask)
    }

    /// Check if IPv6 is within CIDR range
    fn ipv6_in_cidr(&self, ip: &Ipv6Addr, network: &Ipv6Addr, prefix_len: u8) -> bool {
        if prefix_len > 128 {
            return false;
        }

        let ip_bits = u128::from(*ip);
        let network_bits = u128::from(*network);
        let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };

        (ip_bits & mask) == (network_bits & mask)
    }

    /// Check if current time is within time window
    fn is_within_time_window(&self, window: &TimeWindow) -> bool {
        let now = Utc::now();

        // Check day of week
        let current_day = self.weekday_to_string(now.weekday());
        if !window.days.is_empty() && !window.days.contains(&current_day) {
            return false;
        }

        // Parse time window
        let start_time = match NaiveTime::parse_from_str(&window.start, "%H:%M") {
            Ok(t) => t,
            Err(_) => return true, // Invalid format, allow by default
        };

        let end_time = match NaiveTime::parse_from_str(&window.end, "%H:%M") {
            Ok(t) => t,
            Err(_) => return true, // Invalid format, allow by default
        };

        let current_time = now.time();

        // Check if current time is within window
        if start_time <= end_time {
            // Normal case: start before end
            current_time >= start_time && current_time <= end_time
        } else {
            // Wrap-around case: end is next day
            current_time >= start_time || current_time <= end_time
        }
    }

    /// Convert weekday to lowercase string
    fn weekday_to_string(&self, weekday: Weekday) -> String {
        match weekday {
            Weekday::Mon => "mon",
            Weekday::Tue => "tue",
            Weekday::Wed => "wed",
            Weekday::Thu => "thu",
            Weekday::Fri => "fri",
            Weekday::Sat => "sat",
            Weekday::Sun => "sun",
        }.to_string()
    }

    /// Get the highest priority action
    fn get_highest_action<'a>(&self, current: &'a str, new: &'a str) -> &'a str {
        // Action priority: exclude > block > alert > warn > allow
        let priority = |action: &str| -> i32 {
            match action {
                "exclude" => 4,
                "block" => 3,
                "alert" => 2,
                "warn" => 1,
                _ => 0,
            }
        };

        if priority(new) > priority(current) {
            new
        } else {
            current
        }
    }

    /// Validate multiple targets in bulk
    pub fn validate_bulk(&self, targets: &[String], scanner_type: Option<&str>) -> Vec<(String, ValidationResult)> {
        targets.iter()
            .map(|target| (target.clone(), self.validate(target, scanner_type)))
            .collect()
    }

    /// Check if any rules match the target
    pub fn has_matching_rules(&self, target: &str, scanner_type: Option<&str>) -> bool {
        let result = self.validate(target, scanner_type);
        !result.matched_rules.is_empty()
    }

    /// Get all active rules
    pub fn get_active_rules(&self) -> Vec<&ExclusionRule> {
        self.rules.iter().filter(|r| r.is_active).collect()
    }

    /// Update rules (replace all)
    pub fn update_rules(&mut self, rules: Vec<ExclusionRule>) {
        let mut sorted_rules = rules;
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        self.rules = sorted_rules;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(id: i32, rule_type: &str, pattern: &str) -> ExclusionRule {
        ExclusionRule {
            id,
            rule_type: rule_type.to_string(),
            pattern: pattern.to_string(),
            action: "exclude".to_string(),
            scanner_types: vec![],
            time_window: None,
            is_active: true,
            priority: 0,
        }
    }

    #[test]
    fn test_ip_cidr_matching() {
        let rules = vec![
            create_test_rule(1, "cidr", "192.168.1.0/24"),
            create_test_rule(2, "cidr", "10.0.0.0/8"),
        ];

        let validator = ExclusionValidator::new(rules);

        // Should match
        let result = validator.validate("192.168.1.100", None);
        assert!(result.is_excluded);

        let result = validator.validate("10.50.30.20", None);
        assert!(result.is_excluded);

        // Should not match
        let result = validator.validate("192.168.2.100", None);
        assert!(!result.is_excluded);
    }

    #[test]
    fn test_domain_wildcard_matching() {
        let rules = vec![
            create_test_rule(1, "domain", "*.example.com"),
            create_test_rule(2, "domain", "test.internal.local"),
        ];

        let validator = ExclusionValidator::new(rules);

        // Should match
        let result = validator.validate("api.example.com", None);
        assert!(result.is_excluded);

        let result = validator.validate("https://test.internal.local/path", None);
        assert!(result.is_excluded);

        // Should not match
        let result = validator.validate("example.org", None);
        assert!(!result.is_excluded);
    }

    #[test]
    fn test_pattern_matching() {
        let rules = vec![
            create_test_rule(1, "pattern", "*.dev.*"),
            create_test_rule(2, "pattern", "test-*"),
        ];

        let validator = ExclusionValidator::new(rules);

        // Should match
        let result = validator.validate("api.dev.example.com", None);
        assert!(result.is_excluded);

        let result = validator.validate("test-server-01", None);
        assert!(result.is_excluded);
    }

    #[test]
    fn test_scanner_type_filtering() {
        let mut rule = create_test_rule(1, "domain", "example.com");
        rule.scanner_types = vec!["nuclei".to_string()];

        let validator = ExclusionValidator::new(vec![rule]);

        // Should match with correct scanner type
        let result = validator.validate("example.com", Some("nuclei"));
        assert!(result.is_excluded);

        // Should not match with different scanner type
        let result = validator.validate("example.com", Some("nmap"));
        assert!(!result.is_excluded);
    }

    #[test]
    fn test_extract_domain() {
        let validator = ExclusionValidator::new(vec![]);

        assert_eq!(validator.extract_domain("https://example.com/path"), "example.com");
        assert_eq!(validator.extract_domain("http://api.example.com:8080"), "api.example.com");
        assert_eq!(validator.extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_ip() {
        let validator = ExclusionValidator::new(vec![]);

        assert!(validator.extract_ip("192.168.1.1").is_some());
        assert!(validator.extract_ip("https://192.168.1.1/path").is_some());
        assert!(validator.extract_ip("http://192.168.1.1:8080").is_some());
        assert!(validator.extract_ip("example.com").is_none());
    }
}
