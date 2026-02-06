// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use std::collections::{HashMap, HashSet};

/// Extract combo/correlation features that fire when interesting combinations
/// of category features are found. Run AFTER all category extractors.
pub fn extract_combo_features(
    features: &HashMap<String, f64>,
    retry_results: Option<&[HashMap<String, f64>]>,
) -> HashMap<String, f64> {
    let mut combos = HashMap::new();
    let has = |key: &str| features.get(key).map_or(false, |v| *v > 0.5);
    let has_any_prefix =
        |prefix: &str| features.keys().any(|k| k.starts_with(prefix) && features[k] > 0.5);

    // === SQLi combos ===
    let has_sqli_error = has_any_prefix("sqli:error_");
    let has_sqli_union =
        has("sqli:union_select_reflected") || has("sqli:information_schema_leak");
    let has_sqli_time =
        has("sqli:time_delay_detected") || has("sqli:time_delay_proportional");
    let has_sqli_boolean =
        has("sqli:boolean_true_diff") || has("sqli:boolean_content_length_delta");
    let has_sqli_input =
        has("sqli:single_quote_triggers_error") || has("sqli:double_quote_triggers_error");

    if has_sqli_error && has_sqli_union {
        combos.insert("combo:sqli_error_plus_union".into(), 1.0);
    }
    if has_sqli_error && has_sqli_time {
        combos.insert("combo:sqli_error_plus_time".into(), 1.0);
    }
    if has_sqli_boolean && has_sqli_time {
        combos.insert("combo:sqli_boolean_plus_time".into(), 1.0);
    }
    if has_sqli_error && has_sqli_input {
        combos.insert("combo:sqli_error_plus_input_char".into(), 1.0);
    }
    // Count distinct DB error types
    let db_error_count = [
        "mysql",
        "postgresql",
        "mssql",
        "oracle",
        "sqlite",
        "db2",
        "mariadb",
        "generic",
    ]
    .iter()
    .filter(|db| {
        has(&format!("sqli:error_{}_syntax", db)) || has("sqli:error_generic_db")
    })
    .count();
    if db_error_count >= 2 {
        combos.insert("combo:sqli_multiple_db_errors".into(), 1.0);
    }
    if has("sqli:stacked_query_success") && has_sqli_error {
        combos.insert("combo:sqli_stacked_plus_error".into(), 1.0);
    }

    // === XSS combos ===
    let has_xss_reflected =
        has("xss:reflection_unencoded") || has("xss:script_tag_reflected");
    let has_no_csp = has("xss:no_csp_header");

    if has("xss:reflection_unencoded") && has_no_csp {
        combos.insert("combo:xss_reflected_unencoded_no_csp".into(), 1.0);
    }
    if has("xss:script_tag_reflected")
        && has("xss:reflection_in_html_body")
        && has_no_csp
    {
        combos.insert("combo:xss_script_in_html_no_csp".into(), 1.0);
    }
    if has("xss:attribute_breakout") && has("xss:reflection_unencoded") {
        combos.insert("combo:xss_attr_breakout_no_encode".into(), 1.0);
    }
    if has("xss:dom_source_to_sink")
        && (has("xss:innerhtml_assignment") || has("xss:eval_with_user_input"))
    {
        combos.insert("combo:xss_dom_sink_plus_source".into(), 1.0);
    }
    // Check multiple reflection contexts
    let xss_contexts = [
        "html_body",
        "attribute",
        "script_block",
        "style_block",
        "comment",
        "json_response",
        "callback",
    ]
    .iter()
    .filter(|ctx| has(&format!("xss:reflection_in_{}", ctx)))
    .count();
    if xss_contexts >= 2 {
        combos.insert("combo:xss_multiple_contexts".into(), 1.0);
    }
    if has_any_prefix("xss:")
        && features
            .keys()
            .any(|k| k.contains("bypass") && features[k] > 0.5)
        && has_xss_reflected
    {
        combos.insert("combo:xss_bypass_plus_reflection".into(), 1.0);
    }

    // === SSRF combos ===
    if has("ssrf:internal_ip_in_response") && has("ssrf:cloud_metadata_accessed") {
        combos.insert("combo:ssrf_internal_plus_metadata".into(), 1.0);
    }
    if has("ssrf:redirect_to_internal") && has("ssrf:internal_ip_in_response") {
        combos.insert("combo:ssrf_redirect_plus_internal".into(), 1.0);
    }
    if (has("ssrf:file_protocol_accessed")
        || has("ssrf:gopher_protocol_used")
        || has("ssrf:dict_protocol_used"))
        && (has("ssrf:internal_ip_in_response") || has("ssrf:cloud_metadata_accessed"))
    {
        combos.insert("combo:ssrf_protocol_plus_data".into(), 1.0);
    }

    // === Cmdi combos ===
    if has("cmdi:os_command_output") && has("cmdi:time_delay_via_sleep") {
        combos.insert("combo:cmdi_output_plus_delay".into(), 1.0);
    }
    if has("cmdi:dns_lookup_triggered") && has("cmdi:os_command_output") {
        combos.insert("combo:cmdi_dns_plus_output".into(), 1.0);
    }
    let separators = [
        "pipe_operator_works",
        "semicolon_separator",
        "ampersand_chaining",
        "newline_injection",
    ]
    .iter()
    .filter(|s| has(&format!("cmdi:{}", s)))
    .count();
    if separators >= 2 {
        combos.insert("combo:cmdi_multiple_separators".into(), 1.0);
    }

    // === SSTI combos ===
    if has("ssti:math_expression_evaluated") && has("ssti:error_reveals_engine") {
        combos.insert("combo:ssti_math_plus_engine_error".into(), 1.0);
    }
    if has("ssti:rce_via_template") && has("ssti:file_read_via_template") {
        combos.insert("combo:ssti_rce_plus_file_read".into(), 1.0);
    }
    let engines_matched = [
        "jinja2",
        "twig",
        "freemarker",
        "velocity",
        "mako",
        "smarty",
        "pebble",
        "thymeleaf",
        "nunjucks",
        "handlebars",
        "ejs",
        "erb",
        "razor",
    ]
    .iter()
    .filter(|e| has(&format!("ssti:{}_expression_eval", e)))
    .count();
    if engines_matched >= 2 {
        combos.insert("combo:ssti_multiple_engines_match".into(), 1.0);
    }

    // === Cross-category combos ===
    if has_sqli_error
        && (has("info:stack_trace_leaked") || has("info:source_code_in_error"))
    {
        combos.insert("combo:sqli_plus_info_disclosure".into(), 1.0);
    }
    if has_xss_reflected && has_no_csp && has("config:missing_x_content_type") {
        combos.insert("combo:xss_plus_no_security_headers".into(), 1.0);
    }
    if has_any_prefix("ssrf:") && has_any_prefix("traversal:") {
        combos.insert("combo:ssrf_plus_traversal".into(), 1.0);
    }
    if has_any_prefix("auth:") && has_any_prefix("idor:") {
        combos.insert("combo:auth_bypass_plus_idor".into(), 1.0);
    }
    if has_any_prefix("upload:") && has_any_prefix("traversal:") {
        combos.insert("combo:upload_plus_traversal".into(), 1.0);
    }
    if has("csrf:token_not_validated") && has("signal:error_triggered") {
        combos.insert("combo:csrf_plus_state_change".into(), 1.0);
    }

    // Count distinct vuln classes
    let vuln_classes: HashSet<&str> = features
        .keys()
        .filter(|k| features[*k] > 0.5)
        .filter_map(|k| k.split(':').next())
        .filter(|cat| {
            !["signal", "tech", "combo", "severity", "config", "tls", "info"]
                .contains(cat)
        })
        .collect();
    if vuln_classes.len() >= 3 {
        combos.insert("combo:multiple_vuln_classes".into(), 1.0);
    }

    // RCE chain: any path to code execution
    if has("cmdi:os_command_output")
        || has("ssti:rce_via_template")
        || has("ssti:os_command_via_template")
        || has("deser:java_gadget_chain")
        || has("deser:python_pickle_exec")
        || has("proto:rce_via_pollution")
        || has("upload:php_webshell_uploaded")
        || has("upload:jsp_webshell_uploaded")
    {
        combos.insert("combo:rce_chain_confirmed".into(), 1.0);
    }

    // === Confidence from retries ===
    if let Some(retries) = retry_results {
        if retries.len() >= 2 {
            // Check if positive signals are consistent
            let positive_keys: Vec<&String> = features
                .keys()
                .filter(|k| {
                    features[*k] > 0.5
                        && !k.starts_with("signal:")
                        && !k.starts_with("tech:")
                })
                .collect();

            let consistent = positive_keys.iter().all(|k| {
                retries
                    .iter()
                    .all(|r| r.get(*k).map_or(false, |v| *v > 0.3))
            });

            if consistent && !positive_keys.is_empty() {
                combos.insert("combo:consistent_across_retries".into(), 1.0);
            }

            let inconsistent = positive_keys.iter().any(|k| {
                retries
                    .iter()
                    .any(|r| r.get(*k).map_or(true, |v| *v < 0.1))
            });

            if inconsistent {
                combos.insert("combo:intermittent_results".into(), 1.0);
            }
        }
    }

    // Boolean + time both confirm
    if has_sqli_boolean && has_sqli_time {
        combos.insert("combo:time_plus_boolean_confirm".into(), 1.0);
    }
    if (has_sqli_boolean || has_sqli_time) && has_sqli_error {
        combos.insert("combo:blind_plus_error_based".into(), 1.0);
    }

    // Weak signal check: only one low-weight feature fired
    let positive_count = features
        .iter()
        .filter(|(k, v)| {
            **v > 0.5
                && !k.starts_with("signal:")
                && !k.starts_with("tech:")
                && !k.starts_with("severity:")
        })
        .count();
    if positive_count == 1 {
        combos.insert("combo:only_one_weak_signal".into(), 1.0);
    }

    // Contradictory: positive vuln signal + strong FP suppressor in same category
    for prefix in &[
        "sqli:", "xss:", "ssrf:", "traversal:", "cmdi:", "ssti:",
    ] {
        let detections = features
            .iter()
            .any(|(k, v)| k.starts_with(prefix) && *v > 0.5);
        let suppressors = [
            "_baseline",
            "_unrelated",
            "_blocked",
            "_static",
            "_public",
            "_all_inputs",
            "_is_",
        ]
        .iter()
        .any(|s| {
            features
                .keys()
                .any(|k| k.starts_with(prefix) && k.contains(s) && features[k] > 0.5)
        });
        if detections && suppressors {
            combos.insert("combo:contradictory_signals".into(), 1.0);
            break;
        }
    }

    combos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_features(keys: &[&str]) -> HashMap<String, f64> {
        keys.iter().map(|k| (k.to_string(), 1.0)).collect()
    }

    #[test]
    fn test_sqli_error_plus_union() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "sqli:information_schema_leak",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:sqli_error_plus_union"));
    }

    #[test]
    fn test_sqli_error_plus_time() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "sqli:time_delay_detected",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:sqli_error_plus_time"));
    }

    #[test]
    fn test_sqli_boolean_plus_time() {
        let features = make_features(&[
            "sqli:boolean_content_length_delta",
            "sqli:time_delay_proportional",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:sqli_boolean_plus_time"));
        assert!(combos.contains_key("combo:time_plus_boolean_confirm"));
    }

    #[test]
    fn test_sqli_error_plus_input_char() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "sqli:single_quote_triggers_error",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:sqli_error_plus_input_char"));
    }

    #[test]
    fn test_sqli_multiple_db_errors() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "sqli:error_postgresql_syntax",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:sqli_multiple_db_errors"));
    }

    #[test]
    fn test_xss_reflected_unencoded_no_csp() {
        let features = make_features(&[
            "xss:reflection_unencoded",
            "xss:no_csp_header",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:xss_reflected_unencoded_no_csp"));
    }

    #[test]
    fn test_xss_script_in_html_no_csp() {
        let features = make_features(&[
            "xss:script_tag_reflected",
            "xss:reflection_in_html_body",
            "xss:no_csp_header",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:xss_script_in_html_no_csp"));
    }

    #[test]
    fn test_xss_multiple_contexts() {
        let features = make_features(&[
            "xss:reflection_in_html_body",
            "xss:reflection_in_attribute",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:xss_multiple_contexts"));
    }

    #[test]
    fn test_ssrf_internal_plus_metadata() {
        let features = make_features(&[
            "ssrf:internal_ip_in_response",
            "ssrf:cloud_metadata_accessed",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:ssrf_internal_plus_metadata"));
    }

    #[test]
    fn test_ssti_math_plus_engine_error() {
        let features = make_features(&[
            "ssti:math_expression_evaluated",
            "ssti:error_reveals_engine",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:ssti_math_plus_engine_error"));
    }

    #[test]
    fn test_ssti_multiple_engines() {
        let features = make_features(&[
            "ssti:jinja2_expression_eval",
            "ssti:twig_expression_eval",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:ssti_multiple_engines_match"));
    }

    #[test]
    fn test_rce_chain_confirmed() {
        let features = make_features(&["cmdi:os_command_output"]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:rce_chain_confirmed"));
    }

    #[test]
    fn test_multiple_vuln_classes() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "xss:reflection_unencoded",
            "traversal:etc_passwd_content",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:multiple_vuln_classes"));
    }

    #[test]
    fn test_only_one_weak_signal() {
        let features = make_features(&["sqli:error_mysql_syntax"]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:only_one_weak_signal"));
    }

    #[test]
    fn test_contradictory_signals() {
        let features = make_features(&[
            "sqli:error_mysql_syntax",
            "sqli:error_matches_baseline",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:contradictory_signals"));
    }

    #[test]
    fn test_consistent_across_retries() {
        let features = make_features(&["sqli:error_mysql_syntax"]);
        let retry1: HashMap<String, f64> =
            [("sqli:error_mysql_syntax".to_string(), 0.9)].into_iter().collect();
        let retry2: HashMap<String, f64> =
            [("sqli:error_mysql_syntax".to_string(), 0.85)].into_iter().collect();
        let retries = vec![retry1, retry2];
        let combos = extract_combo_features(&features, Some(&retries));
        assert!(combos.contains_key("combo:consistent_across_retries"));
    }

    #[test]
    fn test_intermittent_results() {
        let features = make_features(&["sqli:error_mysql_syntax"]);
        let retry1: HashMap<String, f64> =
            [("sqli:error_mysql_syntax".to_string(), 0.9)].into_iter().collect();
        let retry2: HashMap<String, f64> =
            [("sqli:error_mysql_syntax".to_string(), 0.0)].into_iter().collect();
        let retries = vec![retry1, retry2];
        let combos = extract_combo_features(&features, Some(&retries));
        assert!(combos.contains_key("combo:intermittent_results"));
    }

    #[test]
    fn test_blind_plus_error_based() {
        let features = make_features(&[
            "sqli:time_delay_detected",
            "sqli:error_mysql_syntax",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:blind_plus_error_based"));
    }

    #[test]
    fn test_empty_features_no_combos() {
        let features = HashMap::new();
        let combos = extract_combo_features(&features, None);
        assert!(combos.is_empty());
    }

    #[test]
    fn test_cross_category_ssrf_plus_traversal() {
        let features = make_features(&[
            "ssrf:internal_ip_in_response",
            "traversal:etc_passwd_content",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:ssrf_plus_traversal"));
    }

    #[test]
    fn test_cmdi_multiple_separators() {
        let features = make_features(&[
            "cmdi:pipe_operator_works",
            "cmdi:semicolon_separator",
        ]);
        let combos = extract_combo_features(&features, None);
        assert!(combos.contains_key("combo:cmdi_multiple_separators"));
    }
}
