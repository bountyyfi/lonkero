// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract SSTI (Server-Side Template Injection) features from a probe response
pub fn extract_ssti_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body = &ctx.response.body;

    // Math expression evaluation - the core SSTI signal
    let math_probes: &[(&str, &str)] = &[
        ("{{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),   // Twig-specific
        ("${7*7}", "49"),            // FreeMarker/Mako
        ("<%= 7*7 %>", "49"),        // ERB
        ("#{7*7}", "49"),            // Ruby interpolation
    ];

    for (probe, expected) in math_probes {
        if ctx.probe_payload.contains(probe)
            && body.contains(expected)
            && !ctx.baseline.body.contains(expected)
        {
            features.insert("ssti:math_expression_evaluated".into(), 1.0);

            // Identify specific engine
            match *probe {
                "{{7*7}}" => {
                    features.insert("ssti:jinja2_expression_eval".into(), 0.9);
                    features.insert("ssti:pebble_expression_eval".into(), 0.7);
                    features.insert("ssti:nunjucks_expression_eval".into(), 0.7);
                }
                "{{7*'7'}}" => {
                    features.insert("ssti:twig_expression_eval".into(), 0.95);
                }
                "${7*7}" => {
                    features.insert("ssti:freemarker_expression_eval".into(), 0.8);
                    features.insert("ssti:mako_expression_eval".into(), 0.8);
                }
                "<%= 7*7 %>" => {
                    features.insert("ssti:erb_expression_eval".into(), 0.9);
                    features.insert("ssti:ejs_expression_eval".into(), 0.8);
                }
                _ => {}
            }
            break;
        }
    }

    // Error-based engine detection
    let engine_errors: &[(&str, &str)] = &[
        ("jinja2", "ssti:jinja2_expression_eval"),
        ("twig", "ssti:twig_expression_eval"),
        ("freemarker", "ssti:freemarker_expression_eval"),
        ("velocity", "ssti:velocity_expression_eval"),
        ("thymeleaf", "ssti:thymeleaf_expression_eval"),
        ("smarty", "ssti:smarty_expression_eval"),
        ("mako", "ssti:mako_expression_eval"),
    ];

    let body_lower = body.to_lowercase();
    let baseline_lower = ctx.baseline.body.to_lowercase();
    for (engine, feature_key) in engine_errors {
        if body_lower.contains(engine) && !baseline_lower.contains(engine) {
            features.insert("ssti:error_reveals_engine".into(), 1.0);
            features.insert(feature_key.to_string(), 0.7);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_jinja2_math_eval() {
        let response = make_response("Result: 49", 200);
        let ctx = make_ctx("ssti", "{{7*7}}", response);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        assert!(features.contains_key("ssti:math_expression_evaluated"));
        assert!(features.contains_key("ssti:jinja2_expression_eval"));
    }

    #[test]
    fn test_twig_specific() {
        let response = make_response("Output: 7777777", 200);
        let ctx = make_ctx("ssti", "{{7*'7'}}", response);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        assert!(features.contains_key("ssti:math_expression_evaluated"));
        assert!(features.contains_key("ssti:twig_expression_eval"));
    }

    #[test]
    fn test_no_eval_no_features() {
        let response = make_response("No template evaluation here", 200);
        let ctx = make_ctx("ssti", "{{7*7}}", response);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        assert!(!features.contains_key("ssti:math_expression_evaluated"));
    }

    #[test]
    fn test_baseline_already_has_value() {
        let response = make_response("The answer is 49", 200);
        let mut ctx = make_ctx("ssti", "{{7*7}}", response);
        ctx.baseline = make_response("The answer is 49", 200);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        // Should NOT trigger because baseline already has "49"
        assert!(!features.contains_key("ssti:math_expression_evaluated"));
    }

    #[test]
    fn test_engine_error_detection() {
        let response = make_response(
            "jinja2.exceptions.UndefinedError: 'foo' is undefined",
            500,
        );
        let ctx = make_ctx("ssti", "{{foo}}", response);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        assert!(features.contains_key("ssti:error_reveals_engine"));
        assert!(features.contains_key("ssti:jinja2_expression_eval"));
    }

    #[test]
    fn test_erb_eval() {
        let response = make_response("Value: 49", 200);
        let ctx = make_ctx("ssti", "<%= 7*7 %>", response);
        let mut features = HashMap::new();
        extract_ssti_features(&ctx, &mut features);

        assert!(features.contains_key("ssti:math_expression_evaluated"));
        assert!(features.contains_key("ssti:erb_expression_eval"));
    }
}
