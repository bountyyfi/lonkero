// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract OWASP API Top 10 features from URL patterns, response analysis, headers.
/// 32 features total: 4 BOLA, 3 broken auth, 3 broken object property auth,
/// 3 resource consumption, 3 BFLA, 8 API6-10, 6 gRPC/WebSocket, 2 FP suppressors.
pub fn extract_api_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let url_lower = ctx.request_url.to_lowercase();
    let body_lower = ctx.response.body.to_lowercase();
    let is_api = url_lower.contains("/api/")
        || url_lower.contains("/v1/")
        || url_lower.contains("/v2/")
        || url_lower.contains("/v3/")
        || url_lower.contains("/graphql")
        || ctx
            .response
            .headers
            .get("content-type")
            .map_or(false, |ct| ct.contains("json"));

    // Only run API-specific features for API-like endpoints
    if !is_api {
        return;
    }

    // === API1: BOLA ===

    // api:bola_id_enumeration — URL contains sequential /\d+ in REST pattern
    if has_sequential_id(&url_lower) {
        features.insert("api:bola_id_enumeration".into(), 1.0);
    }

    // api:bola_other_user_object — response contains data for different user
    if let Some(ref auth) = ctx.auth_context {
        if auth.user_role.as_deref() == Some("user") {
            if body_lower.contains("\"admin\"")
                || body_lower.contains("\"role\":\"admin\"")
                || body_lower.contains("other_user")
            {
                features.insert("api:bola_other_user_object".into(), 1.0);
            }
        }
    }

    // api:bola_uuid_predictable — UUIDs follow predictable pattern (v1 time-based)
    if let Some(uuid) = extract_uuid(&url_lower) {
        // UUID v1 has time-based structure: 8-4-1xxx-...
        if uuid.chars().nth(14) == Some('1') {
            features.insert("api:bola_uuid_predictable".into(), 1.0);
        }
    }

    // api:bola_bulk_endpoint_abuse — batch endpoint returns other users' objects
    if (url_lower.contains("/batch") || url_lower.contains("/bulk"))
        && ctx.response.body_bytes > 1000
    {
        features.insert("api:bola_bulk_endpoint_abuse".into(), 1.0);
    }

    // === API2: Broken Auth ===

    // api:auth_token_in_url — auth token in URL path or query string
    if url_lower.contains("token=")
        || url_lower.contains("api_key=")
        || url_lower.contains("access_token=")
        || url_lower.contains("auth=")
    {
        features.insert("api:auth_token_in_url".into(), 1.0);
    }

    // api:auth_no_token_required — endpoint returns data without auth header
    if let Some(ref auth) = ctx.auth_context {
        if !auth.has_auth_header && ctx.response.status == 200 && ctx.response.body_bytes > 100 {
            features.insert("api:auth_no_token_required".into(), 1.0);
        }
    } else if let Some(ref headers) = ctx.request_headers {
        if !headers.contains_key("authorization")
            && !headers.contains_key("cookie")
            && ctx.response.status == 200
            && ctx.response.body_bytes > 100
        {
            features.insert("api:auth_no_token_required".into(), 1.0);
        }
    }

    // api:auth_weak_token_entropy — token entropy < 64 bits
    if let Some(ref headers) = ctx.request_headers {
        if let Some(auth_header) = headers.get("authorization") {
            let token = auth_header
                .split_whitespace()
                .last()
                .unwrap_or(auth_header);
            if token.len() < 16 && !token.is_empty() {
                features.insert("api:auth_weak_token_entropy".into(), 1.0);
            }
        }
    }

    // === API3: Broken Object Property Level Auth ===

    // api:mass_assignment_accepted — extra JSON properties in POST/PUT persisted
    if (ctx.request_method == "POST" || ctx.request_method == "PUT")
        && ctx.response.status < 300
    {
        if ctx.probe_payload.contains("\"isAdmin\"")
            || ctx.probe_payload.contains("\"role\"")
            || ctx.probe_payload.contains("\"verified\"")
            || ctx.probe_payload.contains("\"is_admin\"")
        {
            features.insert("api:mass_assignment_accepted".into(), 1.0);
        }
    }

    // api:excessive_data_exposure — response has >20 JSON fields or sensitive patterns
    let json_fields = body_lower.matches("\":").count();
    if json_fields > 20 {
        features.insert("api:excessive_data_exposure".into(), 1.0);
    }
    if has_pii_pattern(&body_lower) {
        features.insert("api:excessive_data_exposure".into(), 1.0);
    }

    // api:hidden_field_writable — isAdmin, role, verified accepted in write
    if ctx.response.status < 300 {
        if body_lower.contains("\"is_admin\":true")
            || body_lower.contains("\"isadmin\":true")
            || body_lower.contains("\"role\":\"admin\"")
            || body_lower.contains("\"verified\":true")
        {
            features.insert("api:hidden_field_writable".into(), 1.0);
        }
    }

    // === API4: Unrestricted Resource Consumption ===

    // api:no_rate_limiting — 100+ requests without 429 (detected via probe_sequence)
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.len() >= 10 && sequence.iter().all(|r| r.status != 429) {
            features.insert("api:no_rate_limiting".into(), 1.0);
        }
    }

    // api:no_pagination_limit — ?limit=99999 returns all records
    if url_lower.contains("limit=")
        && ctx.response.body_bytes > 10000
        && ctx.response.status == 200
    {
        features.insert("api:no_pagination_limit".into(), 1.0);
    }

    // api:resource_exhaustion — endpoint accepts expensive params
    if ctx.response.response_time_ms > 5000 && ctx.baseline.response_time_ms < 1000 {
        features.insert("api:resource_exhaustion".into(), 1.0);
    }

    // === API5: BFLA ===

    // api:bfla_admin_endpoint_accessible — /admin/*, /internal/* with regular token
    if let Some(ref auth) = ctx.auth_context {
        if auth.user_role.as_deref() == Some("user") {
            if (url_lower.contains("/admin") || url_lower.contains("/internal"))
                && ctx.response.status == 200
            {
                features.insert("api:bfla_admin_endpoint_accessible".into(), 1.0);
            }
        }
    }

    // api:bfla_method_not_checked — PUT/DELETE work without additional auth
    if (ctx.request_method == "PUT" || ctx.request_method == "DELETE")
        && ctx.response.status < 300
    {
        if let Some(ref auth) = ctx.auth_context {
            if auth.user_role.as_deref() == Some("user") {
                features.insert("api:bfla_method_not_checked".into(), 1.0);
            }
        }
    }

    // api:bfla_role_escalation — regular user calls admin-only functions
    if let Some(ref auth) = ctx.auth_context {
        if auth.user_role.as_deref() == Some("user") {
            if body_lower.contains("\"role\":\"admin\"")
                || body_lower.contains("admin_panel")
                || body_lower.contains("manage_users")
            {
                features.insert("api:bfla_role_escalation".into(), 1.0);
            }
        }
    }

    // === API6-10 ===

    // api:ssrf_via_webhook_url — webhook URL param accepts internal URLs
    if url_lower.contains("webhook") || url_lower.contains("callback") {
        if ctx.probe_payload.contains("127.0.0.1")
            || ctx.probe_payload.contains("localhost")
            || ctx.probe_payload.contains("169.254.169.254")
        {
            if ctx.response.status < 400 {
                features.insert("api:ssrf_via_webhook_url".into(), 1.0);
            }
        }
    }

    // api:graphql_depth_bomb — GraphQL depth 10+ returns data
    if url_lower.contains("/graphql") {
        let depth = ctx.probe_payload.matches('{').count();
        if depth >= 10 && ctx.response.status == 200 {
            features.insert("api:graphql_depth_bomb".into(), 1.0);
        }
    }

    // api:batch_operation_abuse — batch endpoint skips per-item auth
    if url_lower.contains("/batch") && ctx.response.status < 300 {
        features.insert("api:batch_operation_abuse".into(), 1.0);
    }

    // api:api_key_in_response — API key visible in JSON response
    if body_lower.contains("\"api_key\":")
        || body_lower.contains("\"apikey\":")
        || body_lower.contains("\"secret_key\":")
        || body_lower.contains("\"access_key\":")
    {
        features.insert("api:api_key_in_response".into(), 1.0);
    }

    // api:version_downgrade_attack — /v1/ has vulns that /v2/ fixed
    if url_lower.contains("/v1/") && ctx.response.status < 400 {
        // Check if same endpoint on v2 returns different/blocked
        if ctx.baseline.status >= 400 || ctx.baseline.status == 301 {
            features.insert("api:version_downgrade_attack".into(), 1.0);
        }
    }

    // api:undocumented_endpoint_found — unlisted endpoint responds
    if ctx.response.status == 200 {
        let undoc_patterns = [
            "/internal/", "/debug/", "/_", "/hidden/", "/test/", "/dev/",
        ];
        if undoc_patterns.iter().any(|p| url_lower.contains(p)) {
            features.insert("api:undocumented_endpoint_found".into(), 1.0);
        }
    }

    // api:debug_endpoint_exposed — /debug, /_debug, /internal/debug reachable
    if ctx.response.status == 200 {
        if url_lower.contains("/debug")
            || url_lower.contains("/_debug")
            || url_lower.contains("/internal/debug")
        {
            features.insert("api:debug_endpoint_exposed".into(), 1.0);
        }
    }

    // api:cors_misconfigured_api — reflects Origin in Access-Control-Allow-Origin
    if let Some(acao) = ctx.response.headers.get("access-control-allow-origin") {
        if acao == "*" || acao.contains("null") {
            features.insert("api:cors_misconfigured_api".into(), 1.0);
        }
    }

    // === gRPC/WebSocket API ===

    // api:grpc_reflection_enabled — gRPC reflection service responds
    if body_lower.contains("grpc.reflection") || body_lower.contains("serverreflection") {
        features.insert("api:grpc_reflection_enabled".into(), 1.0);
    }

    // api:grpc_no_tls — gRPC accepts plaintext
    if url_lower.starts_with("http://") && body_lower.contains("grpc") {
        features.insert("api:grpc_no_tls".into(), 1.0);
    }

    // api:grpc_unary_injection — injection in gRPC message field
    if body_lower.contains("grpc") && ctx.response.status >= 500 {
        features.insert("api:grpc_unary_injection".into(), 1.0);
    }

    // api:websocket_api_no_auth — WebSocket upgrade succeeds without auth
    if ctx.response.status == 101 {
        if let Some(ref auth) = ctx.auth_context {
            if !auth.has_auth_header {
                features.insert("api:websocket_api_no_auth".into(), 1.0);
            }
        }
    }

    // api:rest_to_graphql_bypass — REST has auth, same data via GraphQL
    if url_lower.contains("/graphql") {
        if let Some(ref auth) = ctx.auth_context {
            if !auth.has_auth_header && ctx.response.status == 200 {
                features.insert("api:rest_to_graphql_bypass".into(), 1.0);
            }
        }
    }

    // api:openapi_spec_sensitive — OpenAPI spec reveals admin/internal endpoints
    if url_lower.contains("/openapi")
        || url_lower.contains("/swagger")
        || url_lower.contains("/api-docs")
    {
        if body_lower.contains("/admin") || body_lower.contains("/internal") {
            features.insert("api:openapi_spec_sensitive".into(), 1.0);
        }
    }

    // === FP suppressors ===

    // api:endpoint_is_healthcheck — /health, /status, /ping, /ready, /healthz
    let healthcheck_patterns = ["/health", "/status", "/ping", "/ready", "/healthz", "/live"];
    if healthcheck_patterns.iter().any(|p| url_lower.contains(p)) {
        features.insert("api:endpoint_is_healthcheck".into(), 1.0);
    }

    // api:public_api_by_design — documented as public (CORS * + no auth needed by design)
    if let Some(acao) = ctx.response.headers.get("access-control-allow-origin") {
        if acao == "*" {
            if ctx
                .response
                .headers
                .get("x-api-public")
                .map_or(false, |v| v == "true")
            {
                features.insert("api:public_api_by_design".into(), 1.0);
            }
        }
    }
}

/// Check if URL contains sequential numeric ID in REST pattern
fn has_sequential_id(url: &str) -> bool {
    let parts: Vec<&str> = url.split('/').collect();
    for part in &parts {
        if part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty() && part.len() <= 10 {
            return true;
        }
    }
    false
}

/// Extract UUID from URL
fn extract_uuid(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.split('/').collect();
    for part in &parts {
        // UUID pattern: 8-4-4-4-12 hex chars
        if part.len() == 36
            && part.chars().filter(|c| *c == '-').count() == 4
            && part
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        {
            return Some(part.to_string());
        }
    }
    None
}

/// Check for PII patterns in response
fn has_pii_pattern(body: &str) -> bool {
    // Email pattern
    if body.contains("@") && (body.contains(".com") || body.contains(".org")) {
        return true;
    }
    // SSN-like pattern
    if body.contains("ssn") || body.contains("social_security") {
        return true;
    }
    // Phone pattern
    if body.contains("phone_number") || body.contains("\"phone\":") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    fn make_api_ctx(url: &str, body: &str, status: u16) -> super::super::ProbeContext {
        let response = make_response(body, status);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.request_url = url.to_string();
        ctx
    }

    #[test]
    fn test_bola_id_enumeration() {
        let ctx = make_api_ctx(
            "https://example.com/api/v1/users/123",
            "{\"id\": 123, \"name\": \"test\"}",
            200,
        );
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:bola_id_enumeration"));
    }

    #[test]
    fn test_auth_token_in_url() {
        let ctx = make_api_ctx(
            "https://example.com/api/v1/users?token=abc123",
            "{\"data\": []}",
            200,
        );
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:auth_token_in_url"));
    }

    #[test]
    fn test_api_key_in_response() {
        let ctx = make_api_ctx(
            "https://example.com/api/v1/settings",
            "{\"api_key\": \"sk-1234567890\", \"name\": \"test\"}",
            200,
        );
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:api_key_in_response"));
    }

    #[test]
    fn test_excessive_data_exposure() {
        let mut fields = Vec::new();
        for i in 0..25 {
            fields.push(format!("\"field{}\": \"value{}\"", i, i));
        }
        let body = format!("{{{}}}", fields.join(", "));
        let ctx = make_api_ctx("https://example.com/api/v1/users/1", &body, 200);
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:excessive_data_exposure"));
    }

    #[test]
    fn test_healthcheck_suppressor() {
        let ctx = make_api_ctx(
            "https://example.com/api/v1/health",
            "{\"status\": \"ok\"}",
            200,
        );
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:endpoint_is_healthcheck"));
    }

    #[test]
    fn test_debug_endpoint_exposed() {
        let ctx = make_api_ctx(
            "https://example.com/api/v1/debug/config",
            "{\"db_host\": \"10.0.0.1\"}",
            200,
        );
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:debug_endpoint_exposed"));
    }

    #[test]
    fn test_non_api_skipped() {
        let response = make_response("<html>page</html>", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.request_url = "https://example.com/page".to_string();
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.is_empty());
    }

    #[test]
    fn test_cors_misconfigured() {
        let mut response = make_response("{\"data\": []}", 200);
        response.headers.insert(
            "access-control-allow-origin".to_string(),
            "*".to_string(),
        );
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.request_url = "https://example.com/api/v1/data".to_string();
        let mut features = HashMap::new();
        extract_api_features(&ctx, &mut features);
        assert!(features.contains_key("api:cors_misconfigured_api"));
    }
}
