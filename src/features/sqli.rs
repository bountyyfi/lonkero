// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract SQL injection features from a probe response
pub fn extract_sqli_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body = &ctx.response.body;
    let body_lower = body.to_lowercase();

    // Error-based: check for database error patterns in response

    // sqli:error_mysql_syntax
    if body.contains("You have an error in your SQL syntax")
        || body.contains("mysql_fetch")
        || body.contains("mysqli_")
    {
        features.insert("sqli:error_mysql_syntax".into(), 0.95);
    }

    // sqli:error_postgresql_syntax
    if body.contains("ERROR: syntax error at or near")
        || body.contains("pg_query")
        || body.contains("PG::SyntaxError")
    {
        features.insert("sqli:error_postgresql_syntax".into(), 0.95);
    }

    // sqli:error_mssql_syntax
    if body.contains("Unclosed quotation mark")
        || body.contains("mssql_query")
        || body.contains("Microsoft OLE DB")
    {
        features.insert("sqli:error_mssql_syntax".into(), 0.95);
    }

    // sqli:error_oracle_syntax
    if body.contains("ORA-01756")
        || body.contains("ORA-00933")
        || body.contains("Oracle error")
    {
        features.insert("sqli:error_oracle_syntax".into(), 0.95);
    }

    // sqli:error_sqlite_syntax
    if body.contains("SQLITE_ERROR")
        || (body.contains("near \"") && body.contains("syntax error"))
    {
        features.insert("sqli:error_sqlite_syntax".into(), 0.95);
    }

    // sqli:stack_trace_with_query - SQL query visible in stack trace
    if (body.contains("SELECT") || body.contains("INSERT") || body.contains("UPDATE"))
        && (body.contains("at line")
            || body.contains("stacktrace")
            || body.contains("Traceback"))
    {
        features.insert("sqli:stack_trace_with_query".into(), 0.9);
    }

    // sqli:information_schema_leak
    if body_lower.contains("information_schema") || body_lower.contains("table_schema") {
        features.insert("sqli:information_schema_leak".into(), 0.95);
    }

    // sqli:table_names_leaked - look for common system table patterns
    if body_lower.contains("table_name") && body_lower.contains("table_schema") {
        features.insert("sqli:table_names_leaked".into(), 0.9);
    }

    // Time-based detection
    // sqli:time_delay_detected, sqli:time_delay_proportional
    if let Some(injected_delay) = ctx.injected_delay {
        let actual_delay_s = (ctx.response.response_time_ms as f64) / 1000.0;
        let baseline_s = (ctx.baseline.response_time_ms as f64) / 1000.0;
        let extra_delay = actual_delay_s - baseline_s;

        if extra_delay > (injected_delay * 0.7) {
            features.insert(
                "sqli:time_delay_detected".into(),
                (extra_delay / injected_delay).min(1.0),
            );
        }
        if extra_delay > (injected_delay * 0.8) && extra_delay < (injected_delay * 1.5) {
            features.insert("sqli:time_delay_proportional".into(), 0.95);
        }
    }

    // Boolean-based detection
    if ctx.response.status == ctx.baseline.status {
        let body_diff = body.len() as f64 - ctx.baseline.body.len() as f64;
        if body_diff.abs() > 50.0 {
            // sqli:boolean_content_length_delta
            features.insert(
                "sqli:boolean_content_length_delta".into(),
                (body_diff.abs() / ctx.baseline.body.len().max(1) as f64).min(1.0),
            );
        }
    } else {
        features.insert("sqli:boolean_status_code_diff".into(), 1.0);
    }

    // Input characteristics
    // sqli:single_quote_triggers_error
    if ctx.probe_payload.contains('\'')
        && ctx.response.status >= 400
        && ctx.baseline.status < 400
    {
        features.insert("sqli:single_quote_triggers_error".into(), 1.0);
    }

    // False positive suppression
    // sqli:waf_blocked_response
    if ctx.response.status == 403
        || ctx.response.status == 406
        || body_lower.contains("blocked")
        || body_lower.contains("waf")
        || body_lower.contains("firewall")
        || body_lower.contains("mod_security")
    {
        features.insert("sqli:waf_blocked_response".into(), 1.0);
    }

    // sqli:error_in_unrelated_context - error exists in baseline too
    if ctx.baseline.status >= 500 && ctx.response.status >= 500 {
        features.insert("sqli:error_in_unrelated_context".into(), 1.0);
    }

    // FP suppressors: sqli:error_matches_baseline - baseline already has SQL/error content
    if ctx.baseline.body.contains("SQL")
        || ctx.baseline.body.to_lowercase().contains("error")
    {
        features.insert("sqli:error_matches_baseline".into(), 1.0);
    }

    // sqli:error_on_all_inputs - baseline itself is a 500
    if ctx.baseline.status >= 500 {
        features.insert("sqli:error_on_all_inputs".into(), 1.0);
    }

    // sqli:param_is_boolean_flag - parameter name suggests a boolean toggle, not injectable
    if ["true", "false", "0", "1", "yes", "no"]
        .contains(&ctx.param_name.to_lowercase().as_str())
    {
        features.insert("sqli:param_is_boolean_flag".into(), 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_mysql_error_detection() {
        let response = make_response(
            "You have an error in your SQL syntax near '1' at line 1",
            500,
        );
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:error_mysql_syntax"));
        assert!(*features.get("sqli:error_mysql_syntax").unwrap() > 0.9);
    }

    #[test]
    fn test_postgresql_error_detection() {
        let response = make_response(
            "ERROR: syntax error at or near \"'\" LINE 1: SELECT * FROM users WHERE id = ''",
            500,
        );
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:error_postgresql_syntax"));
    }

    #[test]
    fn test_time_based_detection() {
        let mut response = make_response("OK", 200);
        response.response_time_ms = 5200; // ~5.2 seconds
        let mut ctx = make_ctx("sqli", "1' AND SLEEP(5)--", response);
        ctx.injected_delay = Some(5.0);
        ctx.baseline.response_time_ms = 100;

        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:time_delay_detected"));
        assert!(features.contains_key("sqli:time_delay_proportional"));
    }

    #[test]
    fn test_waf_detection() {
        let response = make_response("Request blocked by firewall", 403);
        let ctx = make_ctx("sqli", "' OR 1=1--", response);
        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:waf_blocked_response"));
    }

    #[test]
    fn test_single_quote_error() {
        let response = make_response("Internal Server Error", 500);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:single_quote_triggers_error"));
    }

    #[test]
    fn test_information_schema_leak() {
        let response = make_response(
            "table_name: users, table_schema: public, information_schema",
            200,
        );
        let ctx = make_ctx("sqli", "' UNION SELECT table_name FROM information_schema.tables--", response);
        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:information_schema_leak"));
        assert!(features.contains_key("sqli:table_names_leaked"));
    }

    #[test]
    fn test_baseline_error_suppression() {
        let mut response = make_response("Internal Server Error", 500);
        response.status = 500;
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.baseline.status = 500;

        let mut features = HashMap::new();
        extract_sqli_features(&ctx, &mut features);

        assert!(features.contains_key("sqli:error_in_unrelated_context"));
    }
}
