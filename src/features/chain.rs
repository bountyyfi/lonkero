// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::Vulnerability;
use std::collections::{HashMap, HashSet};

/// Extract chain features from a set of vulnerabilities.
/// POST-PROCESSING extractor: runs on Vec<Vulnerability> AFTER all scanners complete.
/// Groups findings by target URL, checks if types form known attack chains.
/// 18 features total: 4 info chains, 8 server-side chains, 4 access escalation, 2 meta.
pub fn extract_chain_features(vulns: &[Vulnerability]) -> HashMap<String, f64> {
    let mut features = HashMap::new();

    if vulns.is_empty() {
        return features;
    }

    // Group vulnerabilities by target base URL (scheme + host + path, without query)
    let mut by_target: HashMap<String, Vec<&Vulnerability>> = HashMap::new();
    for vuln in vulns {
        let target = normalize_target(&vuln.url);
        by_target.entry(target).or_default().push(vuln);
    }

    // Also collect by category across all targets for global chain detection
    let mut all_types: HashSet<String> = HashSet::new();
    for vuln in vulns {
        all_types.insert(categorize_vuln(vuln));
    }

    for (_target, target_vulns) in &by_target {
        let types: HashSet<String> = target_vulns.iter().map(|v| categorize_vuln(v)).collect();
        let has = |t: &str| types.contains(t);

        let evidence_contains = |keyword: &str| {
            target_vulns.iter().any(|v| {
                v.evidence
                    .as_ref()
                    .map_or(false, |e| e.to_lowercase().contains(keyword))
            })
        };

        let body_contains = |keyword: &str| {
            target_vulns.iter().any(|v| {
                v.evidence
                    .as_ref()
                    .map_or(false, |e| e.to_lowercase().contains(keyword))
                    || v.description.to_lowercase().contains(keyword)
            })
        };

        // === Info gathering chains ===

        // chain:info_to_sqli — info disclosure + SQLi on same target
        if has("info") && has("sqli") {
            features.insert("chain:info_to_sqli".into(), 1.0);
        }

        // chain:info_to_auth_bypass — info disclosure + auth bypass on same target
        if has("info") && has("auth") {
            features.insert("chain:info_to_auth_bypass".into(), 1.0);
        }

        // chain:error_to_exploitation — verbose error + any injection on same endpoint
        let has_error_info = target_vulns.iter().any(|v| {
            let vt = v.vuln_type.to_lowercase();
            vt.contains("error") || vt.contains("stack trace") || vt.contains("disclosure")
        });
        let has_injection = has("sqli") || has("xss") || has("cmdi") || has("ssti");
        if has_error_info && has_injection {
            features.insert("chain:error_to_exploitation".into(), 1.0);
        }

        // chain:version_to_known_cve — version disclosure + known vulnerable version
        if target_vulns
            .iter()
            .any(|v| v.vuln_type.to_lowercase().contains("version"))
        {
            if target_vulns.iter().any(|v| {
                v.cwe.contains("CVE") || v.description.to_lowercase().contains("cve-")
            }) {
                features.insert("chain:version_to_known_cve".into(), 1.0);
            }
        }

        // === Server-side chains ===

        // chain:ssrf_to_metadata — SSRF + cloud metadata in response
        if has("ssrf") {
            if evidence_contains("169.254.169.254")
                || evidence_contains("accesskeyid")
                || evidence_contains("iam")
            {
                features.insert("chain:ssrf_to_metadata".into(), 1.0);
            }
        }

        // chain:ssrf_to_internal_service — SSRF + internal service data
        if has("ssrf") {
            if evidence_contains("internal") || evidence_contains("localhost") {
                features.insert("chain:ssrf_to_internal_service".into(), 1.0);
            }
        }

        // chain:ssrf_to_rce — SSRF + code execution indicators
        if has("ssrf") && (has("cmdi") || has("ssti")) {
            features.insert("chain:ssrf_to_rce".into(), 1.0);
        }

        // chain:sqli_to_file_read — SQLi + file contents
        if has("sqli") {
            if evidence_contains("root:x:")
                || evidence_contains("load_file")
                || evidence_contains("utl_file")
            {
                features.insert("chain:sqli_to_file_read".into(), 1.0);
            }
        }

        // chain:sqli_to_rce — SQLi + OS command output
        if has("sqli") {
            if evidence_contains("xp_cmdshell")
                || evidence_contains("sys_exec")
                || body_contains("os command")
            {
                features.insert("chain:sqli_to_rce".into(), 1.0);
            }
        }

        // chain:lfi_to_rce — LFI + log file inclusion + injected log entry
        if has("traversal") || has("lfi") {
            if evidence_contains("log") && has_injection {
                features.insert("chain:lfi_to_rce".into(), 1.0);
            }
        }

        // chain:ssti_to_rce — SSTI + OS command execution via template
        if has("ssti") {
            if evidence_contains("os.") || evidence_contains("subprocess") || has("cmdi") {
                features.insert("chain:ssti_to_rce".into(), 1.0);
            }
        }

        // chain:deser_to_rce — deserialization + code execution confirmed
        if has("deser") && (has("cmdi") || evidence_contains("exec")) {
            features.insert("chain:deser_to_rce".into(), 1.0);
        }

        // === Access escalation chains ===

        // chain:auth_bypass_to_admin — auth bypass + admin panel access
        if has("auth") {
            if target_vulns
                .iter()
                .any(|v| v.url.to_lowercase().contains("/admin"))
            {
                features.insert("chain:auth_bypass_to_admin".into(), 1.0);
            }
        }

        // chain:idor_to_account_takeover — IDOR + modify other user's credentials
        if has("idor") {
            if evidence_contains("password")
                || evidence_contains("email")
                || evidence_contains("credential")
            {
                features.insert("chain:idor_to_account_takeover".into(), 1.0);
            }
        }

        // chain:xss_to_account_takeover — XSS + session cookie accessible
        if has("xss") {
            if evidence_contains("cookie") || evidence_contains("httponly") {
                features.insert("chain:xss_to_account_takeover".into(), 1.0);
            }
        }

        // chain:csrf_to_account_takeover — CSRF on password/email change endpoint
        if has("csrf") {
            let on_sensitive = target_vulns.iter().any(|v| {
                let url = v.url.to_lowercase();
                url.contains("/password")
                    || url.contains("/email")
                    || url.contains("/account")
                    || url.contains("/profile")
            });
            if on_sensitive {
                features.insert("chain:csrf_to_account_takeover".into(), 1.0);
            }
        }

        // === Meta ===

        // chain:two_step_confirmed — any 2 different vuln classes on same endpoint
        let vuln_classes: HashSet<&str> = types
            .iter()
            .filter(|t| {
                !["info", "config", "tls", "signal"].contains(&t.as_str())
            })
            .map(|t| t.as_str())
            .collect();
        if vuln_classes.len() >= 2 {
            features.insert("chain:two_step_confirmed".into(), 1.0);
        }

        // chain:three_step_confirmed — 3+ different vuln classes on same endpoint
        if vuln_classes.len() >= 3 {
            features.insert("chain:three_step_confirmed".into(), 1.0);
        }
    }

    features
}

/// Normalize URL to base target (scheme + host + path, no query)
fn normalize_target(url: &str) -> String {
    if let Some(pos) = url.find('?') {
        url[..pos].to_string()
    } else {
        url.to_string()
    }
}

/// Categorize a vulnerability into a standard type
fn categorize_vuln(vuln: &Vulnerability) -> String {
    let vt = vuln.vuln_type.to_lowercase();
    if vt.contains("sql") || vt.contains("sqli") {
        "sqli".into()
    } else if vt.contains("xss") || vt.contains("cross-site scripting") {
        "xss".into()
    } else if vt.contains("ssrf") {
        "ssrf".into()
    } else if vt.contains("traversal") || vt.contains("lfi") {
        "traversal".into()
    } else if vt.contains("command") || vt.contains("cmdi") || vt.contains("rce") {
        "cmdi".into()
    } else if vt.contains("ssti") || vt.contains("template") {
        "ssti".into()
    } else if vt.contains("auth") || vt.contains("jwt") {
        "auth".into()
    } else if vt.contains("idor") {
        "idor".into()
    } else if vt.contains("csrf") {
        "csrf".into()
    } else if vt.contains("deser") {
        "deser".into()
    } else if vt.contains("disclosure") || vt.contains("info") || vt.contains("error") {
        "info".into()
    } else if vt.contains("cors") || vt.contains("config") || vt.contains("header") {
        "config".into()
    } else {
        "other".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};

    fn make_vuln(vuln_type: &str, url: &str) -> Vulnerability {
        Vulnerability {
            id: "test-1".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("id".to_string()),
            payload: "test".to_string(),
            description: "Test vulnerability".to_string(),
            evidence: None,
            cwe: "CWE-89".to_string(),
            cvss: 8.5,
            verified: false,
            false_positive: false,
            remediation: "Fix it".to_string(),
            discovered_at: "2026-01-01T00:00:00Z".to_string(),
            ml_confidence: None,
            ml_data: None,
        }
    }

    #[test]
    fn test_info_to_sqli_chain() {
        let vulns = vec![
            make_vuln("Information Disclosure", "https://example.com/api/users"),
            make_vuln("SQL Injection", "https://example.com/api/users?id=1"),
        ];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:info_to_sqli"));
    }

    #[test]
    fn test_two_step_confirmed() {
        let vulns = vec![
            make_vuln("SQL Injection", "https://example.com/api/users?id=1"),
            make_vuln("XSS", "https://example.com/api/users?name=test"),
        ];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:two_step_confirmed"));
    }

    #[test]
    fn test_three_step_confirmed() {
        let vulns = vec![
            make_vuln("SQL Injection", "https://example.com/api/users?id=1"),
            make_vuln("XSS", "https://example.com/api/users?name=test"),
            make_vuln("Command Injection", "https://example.com/api/users?cmd=ls"),
        ];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:three_step_confirmed"));
    }

    #[test]
    fn test_ssrf_to_metadata() {
        let mut vuln = make_vuln("SSRF", "https://example.com/api/fetch");
        vuln.evidence = Some("Response from 169.254.169.254/latest/meta-data".to_string());
        let vulns = vec![vuln];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:ssrf_to_metadata"));
    }

    #[test]
    fn test_xss_to_account_takeover() {
        let mut vuln = make_vuln("XSS", "https://example.com/search");
        vuln.evidence = Some("Cookie accessible, no HttpOnly flag".to_string());
        let vulns = vec![vuln];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:xss_to_account_takeover"));
    }

    #[test]
    fn test_empty_vulns() {
        let features = extract_chain_features(&[]);
        assert!(features.is_empty());
    }

    #[test]
    fn test_auth_bypass_to_admin() {
        let vulns = vec![make_vuln(
            "Authentication Bypass",
            "https://example.com/admin/dashboard",
        )];
        let features = extract_chain_features(&vulns);
        assert!(features.contains_key("chain:auth_bypass_to_admin"));
    }
}
